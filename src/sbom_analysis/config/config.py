import io
import json
import logging
import lzma
import re
import yaml

from dataclasses import dataclass, asdict, field
from gitlab import Gitlab
from importlib import resources
from os import makedirs, path
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from typing import Optional

from sbom_analysis.util import (
    get_api_data, get_file_data, get_soup, test_url
)

logger = logging.getLogger(__name__)


@dataclass
class PackageInfo:
    """
    Information about a package extracted from the SBOM.
    """

    name: str
    version: str
    package_url: Optional[str] = None
    # Debian-specific downstream repository.
    downstream_repo: Optional[str] = None
    downstream_checkout: Optional[str] = None
    # Package directory inside a shared mono downstream repository. This is
    # only relevant for repositories which hold several source package.
    downstream_path: Optional[str] = None
    # Upstream repository with original changes.
    upstream_repo: Optional[str] = None
    upstream_checkout: Optional[str] = None


def monorepo_downstreams(packages: dict[str, PackageInfo]) -> set[str]:
    """
    Get the downstream repositories which contain multiple unrelated
    packages that map to multiple upstream repositories.

    This concerns repositories such as debcargo-conf, but not repositories
    from which multiple related packages are built, such as util-linux.

    Args:
        packages: The packages of the configuration.

    Returns:
        The downstream repositories mapping to more than one upstream.
    """
    # Collect all upstreams belonging to a specific downstream repository.
    upstreams = dict()
    for package_info in packages.values():
        if package_info.downstream_repo is None:
            continue
        upstreams.setdefault(
            package_info.downstream_repo, set()
        ).add(package_info.upstream_repo)

    # Filter mono repositories based on the number of upstreams a downstream
    # repository serves.
    monorepos = set()
    for repo, seen in upstreams.items():
        known = {upstream for upstream in seen if upstream is not None}
        if len(known) <= 1:
            continue
        monorepos.add(repo)
        logger.info(
            "%s serves %d upstreams and is treated as a mono repository.",
            repo,
            len(known)
        )
    return monorepos


@dataclass
class Config:
    """
    Configuration for SBOM analysis.

    Contains analysis meta information to support reproducibility and an
    easy-to-process representation of packages and their sources.
    """

    name: str = "sbom-analysis"
    # Debian release whose Sources index is searched for packaging
    # repositories.
    release: str = "stable"
    perceval_dir: str = "data/perceval"
    extract_dir: str = "data/extract"
    repo_dir: str = "data/repo"
    analysis_dir: str = "data/analysis"
    history_months: int = 24
    window_months: int = 6
    # Number of months between the start of two consecutive time windows. A
    # shift smaller than window_months yields overlapping time windows. Values
    # below 1 shift the windows without overlapping.
    shift_months: int = 6
    # Number of repositories to analyse in parallel. 1 analyses them one after
    # another, -1 uses all available cores.
    jobs: int = 32
    packages: dict[str, PackageInfo] = field(default_factory=dict)
    metrics: list[str] = field(default_factory=lambda:[
        "project_age",
        "version_age",
        "project_commits",
        "project_developers",
        "commits",
        "commit_trend",
        "merge_ratio",
        "bot_ratio",
        "corrective_count",
        "corrective_ratio",
        "developers",
        "contributor_trend",
        "stayers",
        "stayer_ratio",
        "core_stayers",
        "core_stayer_ratio",
        "leavers",
        "leaver_ratio",
        "core_leavers",
        "core_leaver_ratio",
        "newcomers",
        "newcomer_ratio",
        "pony_factor",
        "churn",
        "churn_per_function",
        "churn_trend",
        "loc",
        "files",
        "functions",
        "function_growth",
        "cyclomatic_complexity",
        "cyclomatic_complexity_per_function",
        "cyclomatic_complexity_trend",
        "tokens",
        "tokens_per_function",
        "tokens_trend",
        # "cppcheck_errors",
        # "cppcheck_error_density",
        # "cppcheck_error_trend",
        # "cppcheck_warnings",
        # "cppcheck_style_issues",
        # "cppcheck_performance_issues",
        # "cppcheck_portability_issues",
        # "cppcheck_total_issues",
        # "cppcheck_total_issue_density",
        # "cppcheck_cwe_count",
        # "cppcheck_cwe_density",
        # "cppcheck_cwe_trend",
        "critical_osv_count",
        "critical_osv_density",
        "high_osv_count",
        "medium_osv_count",
        "low_osv_count",
        "total_osv_count",
        "total_osv_density"
    ])

    def __post_init__(self):
        """
        Resolve the shift between consecutive time windows, so that all
        analyses can rely on a valid value.
        """
        # The Sources index is downloaded once on the first lookup, as it is
        # only needed when repository URLs are resolved.
        self._sources_index = None

        if self.shift_months < 1:
            # Shifting by a full window length results in windows which follow
            # each other directly without overlapping.
            self.shift_months = self.window_months
        elif self.shift_months > self.window_months:
            logger.warning(
                "A shift of %s months is larger than the window length of %s "
                "months. Parts of the history are left out.",
                self.shift_months, self.window_months
            )

        # As only full windows are analysed, the history is left out if it is
        # too short for another window.
        if self.history_months >= self.window_months:
            ignored = (
                self.history_months - self.window_months
            ) % self.shift_months
            if ignored > 0:
                logger.warning(
                    "A history of %s months cannot be covered by windows of "
                    "%s months shifted by %s months. The oldest %s months are "
                    "not analysed.",
                    self.history_months, self.window_months,
                    self.shift_months, ignored
                )

    @staticmethod
    def _load_package_mapping() -> dict:
        """
        Load the repository URLs which were resolved and verified before.

        The mapping is shipped with the tool and maintained manually, as only
        a human can verify that a repository belongs to a package. It is read
        as package data so that it is also found when the tool is installed.

        Returns:
            The mapping, or an empty one if the tool ships without it.
        """
        mapping_file = resources.files(
            "sbom_analysis.resources"
        ).joinpath("package_mapping.json")
        if not mapping_file.is_file():
            logger.warning("Package mapping not found. Start scraping...")
            return {}

        with mapping_file.open("r") as f:
            return json.load(f)

    @staticmethod
    def _parse_sources_index(raw: bytes) -> dict[str, str]:
        """
        Extract the packaging repositories from a compressed Sources index.

        Args:
            raw: The compressed index as published by the Debian archive.

        Returns:
            A mapping from source package name to repository URL.
        """
        index = {}
        name = None
        with lzma.open(
                io.BytesIO(raw), "rt", encoding="utf-8", errors="replace"
        ) as f:
            for line in f:
                if line.startswith("Package:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Vcs-Git:") and name is not None:
                    # The field may name a branch or subdirectory behind the
                    # URL, which is not part of the repository location.
                    value = line.split(":", 1)[1].split()
                    if value:
                        index[name] = value[0]
        return index

    def _load_sources_index(self) -> dict[str, str]:
        """
        Read the packaging repository of every Debian source package.

        The archive documents the Vcs-Git field of all source packages of a
        release in its Sources index. Reading it once resolves nearly all
        downstream repositories.

        Returns:
            A mapping from source package name to repository URL, which is
            empty if the index is unavailable.
        """
        # The Debian archive publishes the packaging repository of every source
        # package in its Sources index.
        sources_index_url = (
            "https://deb.debian.org/debian/dists/{release}/{component}/source/"
            "Sources.xz"
        )
        sources_index_components = (
            "main", "contrib", "non-free", "non-free-firmware"
        )

        index = {}
        for component in sources_index_components:
            url = sources_index_url.format(
                release=self.release, component=component
            )
            try:
                raw = get_file_data(url)
                if raw is not None:
                    index.update(self._parse_sources_index(raw))
            except Exception as e:
                logger.debug("Could not read the Sources index %s.", url)
                logger.debug(e, exc_info=True)

        if index:
            logger.info(
                "Read %s packaging repositories from the Sources index of "
                "the %s release.",
                len(index), self.release
            )
        else:
            logger.warning(
                "No Sources index available for the %s release. Falling back "
                "to scraping.",
                self.release
            )
        return index

    def _find_repo_url_from_sources_index(
            self,
            package_name: str
    ) -> str | None:
        """
        Look the packaging repository up in the Debian Sources index.

        Args:
            package_name: Name of the source package to look up.

        Returns:
            The git repository URL if the release documents one, None
            otherwise.
        """
        if self._sources_index is None:
            self._sources_index = self._load_sources_index()

        repo_url = self._sources_index.get(package_name)
        if repo_url is not None:
            logger.debug(
                "Found %s repository in the Sources index.", package_name
            )
        return repo_url

    @staticmethod
    def _described_packages(document: Document) -> set[str]:
        """
        Collect the packages which the SBOM describes as a whole.

        An SBOM lists the system or container image it was generated for as a
        package of its own. Such an entry is not a software package, has no
        repository, and would otherwise be pointlessly searched for on every
        run.

        Args:
            document: The parsed SBOM.

        Returns:
            The SPDX identifiers of the described packages.
        """
        return {
            r.related_spdx_element_id for r in document.relationships
            if r.relationship_type == RelationshipType.DESCRIBES
        }

    @staticmethod
    def _get_upstream_name_from_purl(p: Package) -> str | None:
        """
        Extract the upstream source package name from the purl upstream=
        parameter.

        This is the most reliable source for the upstream name since it is
        directly encoded in the SBOM. For example:
          pkg:deb/debian/login@...?upstream=shadow  →  "shadow"
          pkg:deb/debian/libacl1@...?upstream=acl   →  "acl"

        Args:
            p: The SPDX package object.

        Returns:
            The upstream package name if present, None otherwise.
        """
        if p.external_references:
            for ref in p.external_references:
                if ref.reference_type == "purl" and "upstream=" in ref.locator:
                    up = ref.locator.split("upstream=", 1)[-1]
                    # Strip any further purl query params and version suffix
                    up = up.split("&")[0].split("@")[0]
                    # Strip purl-encoded characters after the name
                    up = up.split("%")[0] if "%" in up else up
                    if up and up != p.name:
                        return up
        return None

    @staticmethod
    def _find_repo_url_from_tracker(package_name: str) -> str | None:
        """
        Search the git repository URL in the Debian package tracker.

        Args:
            package_name: Name of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s repository via package tracker...",
            package_name
        )
        url = "https://tracker.debian.org/pkg/" + package_name

        try:
            soup = get_soup(url)
            if soup is None:
                return None
            vcs_link = soup.find("a", {"rel": "vcs-git"})
            if vcs_link:
                return vcs_link["href"]
        except Exception as e:
            logger.debug(
                "Could not find %s repository via package tracker.",
                package_name
            )
            logger.debug(e, exc_info=True)

    @staticmethod
    def _find_repo_url_from_sources(
            package_name: str,
            version: str
    ) -> str | None:
        """
        Search the git repository URL in the Debian sources.

        Args:
            package_name: Name of the package to look up.
            version: Version of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s repository via sources...",
            package_name
        )
        url = f"https://sources.debian.org/src/{package_name}/" \
              f"{version}/debian/watch"

        try:
            soup = get_soup(url)
            if soup is None:
                return None
            elements = soup.select("code span")
            for e in elements:
                if "git" in e.get_text():
                    repo_url = e.get_text().lstrip(" ").split(" ")[0]
                    return repo_url
        except Exception as e:
            logger.debug("Could not find %s repository via sources.",
                         package_name)
            logger.debug(e, exc_info=True)

    @staticmethod
    def _find_repo_in_github_org(
            homepage: str,
            package_name: str
    ) -> str | None:
        """
        Search the git repository link from the GitHub organisation page.

        Args:
            homepage: URL of the GitHub organisation page.
            package_name: Name of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s repository via GitHub organisation...",
            package_name
        )

        try:
            soup = get_soup(homepage)
            if soup is None:
                return None
            repos = soup.find_all("a", itemprop="name codeRepository")

            href = None
            # Try to find a repository with the exact package name.
            for r in repos:
                if r.get_text() == package_name:
                    href = r.get("href")
            # If the above fails, try to match a similar name. For instance,
            # some packages have a "lib" prefix and/or a numerical suffix.
            if href is None:
                for r in repos:
                    if package_name.startswith("lib") and \
                        r.get_text() == re.sub(
                        r"\d.*", "", package_name[3:]
                    ) or r.get_text() == re.sub(
                        r"\d.*", "", package_name
                    ):
                        href = r.get("href")
            return homepage + "/" + href.split("/")[-1]
        except Exception as e:
            logger.debug(
                "Could not find %s repository via GitHub organisation.",
                package_name
            )
            logger.debug(e, exc_info=True)

    @staticmethod
    def _find_repo_in_gitlab_org(
            homepage: str,
            package_name: str
    ) -> str | None:
        """
        Search the git repository link from the Gitlab organisation page.

        Args:
            homepage: URL of the Gitlab organisation page.
            package_name: Name of the package to look up.
        """
        gl = Gitlab("https://gitlab.com")
        group_path = homepage.split("/")[-1]
        group = gl.groups.get(group_path)

        projects = group.projects.list(get_all=True)
        for project in projects:
            if project == package_name:
                return project.http_url_to_repo
        return None

    @staticmethod
    def _find_homepage_from_tracker(package_name: str) -> str | None:
        """
        Search the homepage link of the package from the Debian package
        tracker.

        Args:
            package_name: Name of the package to look up.

        Returns:
            The homepage URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s homepage via package tracker...",
            package_name
        )
        url = "https://tracker.debian.org/pkg/" + package_name

        try:
            soup = get_soup(url)
            if soup is None:
                return None
            elements = soup.select("a")
            for e in elements:
                if "homepage" in e.get_text():
                    return e.get("href")
        except Exception as e:
            logger.debug(
                "Could not find %s homepage via package tracker.",
                package_name
            )
            logger.debug(e)

    @staticmethod
    def _find_repo_url_from_homepage(homepage: str) -> str | None:
        """
        Search the git repository URL on a package's project homepage.

        Args:
            homepage: URL of the project homepage.

        Returns:
            The git repository URL if found, None otherwise.
        """
        if not homepage.startswith(("http://", "https://")):
            return None

        def has_repo_url(el) -> bool:
            if el.has_attr("href") and "git" in el.get("href") and \
                    ("git" in el.get_text().lower() or
                     "develop" in el.get_text().lower() or
                     "contribu" in el.get_text().lower()):
                return True
            return False

        try:
            soup = get_soup(homepage)
            # Guard against get_soup() returning None
            if soup is None:
                return None
            elements = soup.select("a")

            # Search repository URL by repository-related keywords.
            for e in elements:
                if has_repo_url(e):
                    url = e.get("href")
                    if url.endswith(".html"):
                        # The link refers to another page on the project
                        # homepage. Try to parse the reference page in case the
                        # repository URL is there.
                        if homepage.endswith("/"):
                            url = homepage + e.get("href")
                        else:
                            url = homepage + "/" + e.get("href")

                        next_soup = get_soup(url)
                        if next_soup is None:
                            continue
                        next_elements = next_soup.select("a")
                        for el in next_elements:
                            if has_repo_url(el):
                                n_url = el.get("href")
                                if n_url.startswith("http") or \
                                        n_url.startswith("git"):
                                    return n_url
                    elif url.startswith("http") or url.startswith("git"):
                        # The link is likely related to the git repository.
                        return url

            # If the above fails, try to find a repository URL by more generic
            # keywords.
            for e in elements:
                if "download" in e.get_text().lower() and e.has_attr("href"):
                    url = e.get("href")
                    if url.endswith(".html"):
                        if homepage.endswith("/"):
                            page_url = homepage + e.get("href")
                        else:
                            page_url = homepage + "/" + e.get("href")

                        next_soup = get_soup(page_url)
                        if next_soup is None:
                            continue
                        next_elements = next_soup.select("a")
                        for el in next_elements:
                            if has_repo_url(el):
                                n_url = el.get("href")
                                if n_url.startswith("http") or \
                                        n_url.startswith("git"):
                                    return n_url
        except Exception as e:
            logger.debug(
                "Could not find repository via project homepage %s.",
                homepage
            )
            logger.debug(e, exc_info=True)
        return None

    @staticmethod
    def _find_repo_url_from_github(package_name: str) -> str | None:
        """
        Guess common GitHub repository URL patterns to recover the URL.

        Args:
            package_name: Name of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s repository by guessing GitHub URLs...",
            package_name
        )

        url = "https://github.com/" + package_name + "/" + package_name
        if test_url(url):
            return url

        # If the guessed page does not exist, try common variants such as
        # the package name without the "lib" prefix or without numerical
        # suffixes.
        if package_name.startswith("lib"):
            package_name = re.sub(r"\d.*", "", package_name[3:])
        else:
            package_name = re.sub(r"\d.*", "", package_name)
        url = "https://github.com/" + package_name + "/" + package_name
        return url if test_url(url) else None

    @staticmethod
    def _find_repo_url_from_savannah(package_name: str) -> str | None:
        """
        Guess common GNU Savannah Git repository patterns to recover the URL.

        Args:
            package_name: Name of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug(
            "Searching %s repository by guessing Savannah Git URLs...",
            package_name
        )

        url = f"https://cgit.git.savannah.gnu.org/cgit/{package_name}.git"
        if test_url(url):
            return url
        else:
            url = f"https://savannah.gnu.org/projects/{package_name}"
            if test_url(url):
                url = re.sub("https://", "https://git.", url)
                url = re.sub("/projects/", "/git/", url)
                return url
        return None

    @staticmethod
    def _find_repo_url_from_salsa(package_name: str) -> str | None:
        """
        Guess Salsa repository URL patterns for common Debian team namespaces.

        Args:
            package_name: Name of the package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        logger.debug("Guessing Salsa URL for %s...", package_name)
        patterns = [
            f"https://salsa.debian.org/debian/{package_name}.git",
            f"https://salsa.debian.org/apt-team/{package_name}.git"
        ]
        for url in patterns:
            if test_url(url):
                return url
        return None

    @staticmethod
    def _find_upstream_url_from_crates_io(package_name: str) -> str | None:
        """
        Search the repository of a Rust crate in the crates.io registry.

        Debian packages all Rust crates in a single repository,
        debcargo-conf, and generates their packaging while building. The
        correct upstream repository is determined by the crates.io registry.

        Args:
            package_name: Name of the Debian package to look up.

        Returns:
            The git repository URL if found, None otherwise.
        """
        # Debian names its Rust packages after the crate they package and
        # appends the API version if it ships several versions of a crate,
        # e.g. rust-strsim-0.10.
        if not package_name.startswith("rust-"):
            return None

        crate = re.sub(r"-\d[\d.]*$", "", package_name.removeprefix("rust-"))
        if not crate:
            return None

        logger.debug("Searching %s repository via crates.io...", crate)
        crates_registry = "https://crates.io/api/v1/crates/"
        try:
            data = get_api_data(crates_registry + crate)
        except Exception as e:
            logger.debug("Could not look up crate %s: %s", crate, e)
            return None

        repo_url = (data or {}).get("crate", {}).get("repository")
        return repo_url if repo_url else None

    @staticmethod
    def _get_package_url(p: Package) -> str | None:
        """
        Helper function to extract a package URL from a package.

        Args:
            p: The SPDX package object to extract the package URL for.

        Returns:
            The package URL if found, None otherwise.
        """
        if p.external_references:
            for ref in p.external_references:
                if ref.reference_type == "purl":
                    return ref.locator
        return None

    def _get_repository_url(self, p: Package) -> str | None:
        """
        Helper function to determine the most accurate git repository URL for a
        given package.

        The search order is:
           1. VCS reference directly in the SBOM
           2. Upstream name from purl in the Sources index and the tracker
           3. Package name in the Sources index and the tracker
           4. debian/watch in sources.debian.org
           5. Homepage from the SBOM
           6. Any git link on the homepage
           7. Homepage from the tracker, scanned the same way
           8. Salsa URL guessing
           9. GitHub / Savannah URL guessing
          10. Similar name variants

        Args:
            p: The SPDX package object to extract the git repository URL for.

        Returns:
            The git repository URL if found, None otherwise.
        """
        # 1. Ideally, the repository URL is documented in the SBOM.
        if p.external_references:
            for ref in p.external_references:
                if ref.reference_type == "vcs" or "git" in ref.locator:
                    return ref.locator.split(" ", 1)[0]

        logger.info(
            "Repository URL missing in SBOM for %s. Retrieving it from "
            "other sources.",
            p.spdx_id
        )

        # 2. Use the purl upstream= name early as the primary lookup key.
        # This correctly resolves split-packages, e.g.: shadow entry for the
        # login package.
        up_name = self._get_upstream_name_from_purl(p)
        if up_name is not None:
            # The archive's Sources index documents the same repository as the
            # tracker, so it is searched first to avoid unnecessary requests.
            repo_url = self._find_repo_url_from_sources_index(up_name)
            if repo_url is None:
                # Only if we cannot find the package in the Sources index, we
                # start scraping.
                repo_url = self._find_repo_url_from_tracker(up_name)
            if repo_url is not None:
                return repo_url

        # 3. Search by the package's own name in the Debian archive.
        repo_url = self._find_repo_url_from_sources_index(p.name)
        if repo_url is None:
            repo_url = self._find_repo_url_from_tracker(p.name)
        if repo_url is not None:
            return repo_url

        # 4. For source packages, try debian/watch in sources.debian.org.
        if p.spdx_id.endswith("-srcpkg"):
            repo_url = self._find_repo_url_from_sources(p.name, p.version)
            if repo_url is not None:
                return repo_url

        # 5. Derive from homepage if it directly encodes a git URL.
        if p.homepage and "git" in p.homepage:
            # Check if it is a GitHub URL.
            if re.match(
                    r"^(?:https?://)?github\.com/[^/]+/[^/]+/?$",
                    p.homepage
            ):
                return p.homepage

            # Try to reconstruct the repository URL from GitHub pages.
            if "github.io" in p.homepage:
                username = p.homepage.split(".")[0].split("/")[-1]
                repo = p.homepage.split("/")[-1]
                if len(username) > 0 and len(repo) > 0:
                    return f"https://github.com/{username}/{repo}"

            # Find repository from organisation's page.
            if re.match(
                    r"^(?:https?://)?github\.com/[^/]+/?$",
                    p.homepage
            ):
                repo_url = self._find_repo_in_github_org(p.homepage, p.name)
                if repo_url is not None:
                    return repo_url

        # 6. Scrape the project homepage for any git link.
        if p.homepage:
            repo_url = self._find_repo_url_from_homepage(p.homepage)
            if repo_url is not None:
                return repo_url

        # 7. Retrieve homepage from tracker and scrape it.
        homepage = self._find_homepage_from_tracker(p.name)
        if homepage is not None:
            repo_url = self._find_repo_url_from_homepage(homepage)
            if repo_url is not None:
                return repo_url

        # 8. Guess Salsa URLs, which must not take precedence over the
        # documented repository URLs above, as Salsa also answers for
        # repositories which do not exist. Guessing Salsa URLs is more
        # reliable than guessing on other hosts, as all packages are Debian
        # packages, so it runs first among the guesses.
        for name in ([up_name, p.name] if up_name is not None else [p.name]):
            repo_url = self._find_repo_url_from_salsa(name)
            if repo_url is not None:
                return repo_url

        # 9. Guess GitHub / Savannah URLs.
        repo_url = self._find_repo_url_from_github(p.name)
        if repo_url is not None:
            return repo_url

        repo_url = self._find_repo_url_from_savannah(p.name)
        if repo_url is not None:
            return repo_url

        # 10. Retry with common name variants (lib-prefix, digit-suffix).
        similar_names = [
            p.name.split("-")[0],
            re.sub(r"\d.*", "", p.name.removeprefix("lib")),
        ]
        # Also include the upstream name as a search key if not already tried.
        if up_name is not None:
            similar_names.append(up_name)

        for s in similar_names:
            if not s or s == p.name:
                continue

            repo_url = self._find_repo_url_from_sources_index(s)
            if repo_url is None:
                repo_url = self._find_repo_url_from_tracker(s)
            if repo_url is not None:
                return repo_url

            homepage = self._find_homepage_from_tracker(s)
            if homepage is not None:
                repo_url = self._find_repo_url_from_homepage(homepage)
                if repo_url is not None:
                    return repo_url

            repo_url = self._find_repo_url_from_github(s)
            if repo_url is not None:
                return repo_url

            repo_url = self._find_repo_url_from_savannah(s)
            if repo_url is not None:
                return repo_url

        # The best approach would probably be to extract the information
        # directly from the Debian system of interest.
        # However, this would require access to the system where the SBOM was
        # generated and the VCS link may be missing there as well.
        logger.warning(
            "Failed to retrieve repository URL for %s. Skipping.",
            p.spdx_id
        )
        return None

    def _extract_upstream_url_from_content(
            self,
            text: str,
            package_name: str
    ) -> str | None:
        """
        Helper function to extract an upstream git repository's URL from
        text content (e.g. debian/upstream/metadata, debian/control, etc.).

        Args:
            text: The text content to scan.
            package_name: The package name to match.

        Returns:
            The git repository URL if found, None otherwise.
        """
        try:
            for line in text.splitlines():
                # Skip comments which may contain deprecated information.
                if line.startswith("#"):
                    continue

                # Skip Vcs-* fields as they always point back to the
                # Debian repository itself.
                if line.startswith("Vcs-"):
                    continue

                if line.startswith("Repository"):
                    repo_url = line.split(": ")[-1].strip()
                    if len(repo_url) > 0:
                        return repo_url

                if line.startswith("Homepage"):
                    repo_url = line.split(": ")[-1].strip()
                    if len(repo_url) > 0:
                        if "git" in line:
                            return repo_url
                        else:
                            repo_url = self._find_repo_url_from_homepage(
                                repo_url
                            )
                            if repo_url is not None:
                                if re.match(
                                        r"^(?:https?://)?gitlab\.com/[^/]+/?$",
                                        repo_url
                                ):
                                    repo_url = self._find_repo_in_gitlab_org(
                                        repo_url, package_name
                                    )
                                    if repo_url is not None:
                                        return repo_url
                                return repo_url

                if line.startswith("Source"):
                    repo_url = line.split(": ")[-1].strip()
                    if len(repo_url) > 0:
                        if "git" in repo_url:
                            return repo_url
                        else:
                            repo_url = self._find_repo_url_from_homepage(
                                repo_url
                            )
                            if repo_url is not None:
                                return repo_url

                git_url = re.search(r"git://\S+", line)
                if git_url is not None:
                    return git_url.group()

                git_url = re.search(r"https://git\.\S+", line)
                if git_url is not None:
                    url = git_url.group()
                    # Reject -documentation repos; try -userspace instead.
                    if url.endswith("-documentation.git"):
                        corrected = url.replace(
                            "-documentation.git", "-userspace.git"
                        )
                        if test_url(corrected):
                            return corrected
                        corrected = re.sub(
                            r"-documentation\.git$", ".git", url
                        )
                        if test_url(corrected):
                            return corrected
                        continue
                    return url

                github_url = re.search(
                    r"^(?:https?://)?github\.com/[^/]+/[^/]+/?$",
                    line
                )
                if github_url is not None:
                    url = github_url.group()
                    # Reject -documentation repos (same heuristic for GitHub).
                    if url.rstrip("/").endswith("-documentation"):
                        corrected = url.rstrip("/").replace(
                            "-documentation", "-userspace"
                        )
                        if test_url(corrected + ".git"):
                            return corrected
                    return url

                gitlab_url = re.search(r"https://gitlab\.\S+", line)
                if gitlab_url is not None:
                    return gitlab_url.group()

                cgit_url = re.search(r"https://cgit\.\S+", line)
                if cgit_url is not None:
                    return cgit_url.group()

        except Exception as e:
            logger.debug(e, exc_info=True)
        return None

    def _find_upstream_url_from_gitlab(self, debian_url: str) -> str | None:
        """
        Helper function to extract the upstream repository URL from a Debian
        package repository on Salsa via the GitLab API.

        Args:
            debian_url: The Debian repository URL to extract the upstream URL
            from.

        Returns:
            The upstream repository URL if found, None otherwise.
        """
        package_name = debian_url.split("/")[-1].removesuffix(".git")

        try:
            gl = Gitlab("https://salsa.debian.org")
            project_path = debian_url.split("debian.org/")[-1].removesuffix(".git")
            project = gl.projects.get(project_path)
            branch_name = project.default_branch
        except Exception as e:
            logger.debug(e, exc_info=True)
            return None

        if not branch_name:
            return None

        # Filter salsa URLs to avoid returning a Salsa fork of another Salsa
        # project as "upstream".
        if hasattr(project, "forked_from_project"):
            upstream = project.forked_from_project
            repo_url = upstream.get("http_url_to_repo")
            if repo_url is not None and "salsa.debian" not in repo_url:
                return repo_url

        # Scan common files for upstream URL hints via API (no HTTP scraping).
        files = (
            "debian/upstream/metadata", "debian/upstream-metadata",
            "debian/control",
            "CONTRIBUTING.md", "Documentation/howto-contribute.txt",
            "debian/copyright",
            "debian/watch",
            "build/README.md", "debian/README.source",
            "README.md", "README",
        )
        for f in files:
            logger.debug(
                "Trying to find upstream repository URL for %s in %s...",
                package_name, f
            )
            try:
                file_info = project.files.get(file_path=f, ref=branch_name)
                content = file_info.decode().decode("utf-8")
                repo_url = self._extract_upstream_url_from_content(
                    content, package_name
                )
                if repo_url is not None and "salsa.debian" not in repo_url:
                    return repo_url
            except Exception as e:
                logger.debug("Could not read %s via API: %s", f, e)
                continue

        # Fallback: try GNU Savannah patterns using the package name and
        # common Debian naming variants.
        savannah_names = [
            package_name,
            package_name.removeprefix("pkg-"),
            package_name.replace("lib", "", 1),
        ]
        for s in savannah_names:
            repo_url = self._find_repo_url_from_savannah(s)
            if repo_url is not None:
                return repo_url

        return None

    @staticmethod
    def _process_url(url: str) -> str | None:
        """
        Post-process extracted repository URLs to ensure they can be cloned.

        Args:
            url: The repository URL to process.

        Returns:
            The well-formatted repository URL.
        """
        # Filter accidentally identified SVN repositories.
        if "svn" in url and "git" not in url:
            return None

        # Strip branch info appended after a space bracket, e.g. "url [branch=x]"
        url = re.split(r"\s+\[", url)[0].strip()

        # Normalise the scheme. The archive still declares repositories with
        # the anonymous git protocol, which most hosts stopped serving, and a
        # few with plain http. This runs before the host-specific rules below,
        # so that they apply to the rewritten URL as well.
        url = re.sub(r"^(?:git|http)://", "https://", url)

        # Drop a colon which separates the host from the path without naming a
        # port, e.g. https://salsa.debian.org:/science-team/qd.git.
        url = re.sub(r"^(https://[^/:]+):(?=/)", r"\1", url)

        # Truncate GitHub/GitLab URLs to owner/repo and removes release paths,
        # archive download URLs, etc.
        url = re.sub(r"^(https://github\.com/[^/]+/[^/]+/).*$",
                     r"\1", url).removesuffix("/")
        url = re.sub(r"^(https://gitlab\.com/[^/]+/[^/]+/).*$",
               r"\1", url).removesuffix("/")

        # GitLab/Salsa separates repository paths from other pages by /-/,
        # This removes in URLs such as
        # https://gitlab.gnome.org/GNOME/glib/-/work_items.
        url = re.sub(r"^(https://[^/]+/.+?)/-/.*$", r"\1", url)
        url = re.sub(r'[)\].,]+$', '', url)

        # Strip anything after .git/ (e.g. ?h=master query params on cgit).
        url = re.sub(r"\.git/.*$", "", url)

        # Reformat cgit browser URLs to plain git URLs.
        if url.startswith("https://cgit.") or "/cgit/" in url:
            url = url.replace("//cgit.", "//")
            url = url.replace("/cgit/", "/git/")

        # Reformat gitweb browser URLs. This corrects URLs such as
        # https://sourceware.org/git/?p=bzip2.git;a=summary.git
        url = url.replace("gitweb.cgi?p=", "")
        url = url.replace("?p=", "")
        url = re.sub(r"\.git(?!.*\.git).*$", ".git", url)

        # Fix kernel.org shorthand paths.
        url = url.replace("git.kernel.org/utils",
                          "git.kernel.org/pub/scm/utils")
        url = url.replace("git.kernel.org/git/libs",
                          "git.kernel.org/pub/scm/libs")

        # Ensure that the repository URL ends with .git.
        if not url.endswith(".git"):
            url += ".git"
        return url

    @staticmethod
    def _mapped_repo_url(mapped: dict, role: str) -> str | None:
        """
        Extract a repository URL from the package mapping only if a human
        confirmed it.

        Args:
            mapped: The mapping entry of the package.
            role: Either "downstream" or "upstream".

        Returns:
            The URL if it was verified, None otherwise.
        """
        url = mapped.get(role)
        if not url:
            return None

        if not mapped.get(f"{role}_verified"):
            logger.debug(
                "Searching the %s repository again, as %s is not verified.",
                role, url
            )
            return None

        logger.info(
            "Using the verified %s repository URL %s.",
            role, url
        )
        return url

    @staticmethod
    def _verified_absent(mapped: dict, role: str) -> bool:
        """
        Report whether a human confirmed that a repository does not exist.

        An empty URL which is marked as verified documents that the package
        has no such repository, e.g. because Debian maintains it itself or
        because upstream only publishes release archives. Searching for it
        again could reintroduce a wrong URL. Therefore, it must be skipped.

        Args:
            mapped: The mapping entry of the package.
            role: Either "downstream" or "upstream".

        Returns:
            True if the mapping documents that no repository exists.
        """
        return not mapped.get(role) and bool(mapped.get(f"{role}_verified"))

    @staticmethod
    def _record_resolved_urls(
            discovered: dict,
            static_mapping: dict,
            lookup_name: str,
            downstream_repo: str | None,
            upstream_repo: str | None
    ) -> None:
        """
        Remember a resolved repository URL for manual review.

        Only the URLs which this run resolved are recorded, so an entry
        documents what is left to review. A URL which is verified in the
        mapping is not repeated, as recording it as unverified would
        misrepresent the review it already passed. Entries therefore have to
        be merged per field, not as a whole.

        Args:
            discovered: Resolved URLs collected so far.
            static_mapping: The mapping maintained manually.
            lookup_name: Name the package was looked up by.
            downstream_repo: Resolved downstream repository URL, if any.
            upstream_repo: Resolved upstream repository URL, if any.
        """
        mapped = static_mapping.get(lookup_name, {})
        resolved = {}

        if downstream_repo and not mapped.get("downstream_verified"):
            resolved["downstream"] = downstream_repo
        if upstream_repo and not mapped.get("upstream_verified"):
            resolved["upstream"] = upstream_repo

        if not resolved:
            return

        entry = {}
        for role in ("downstream", "upstream"):
            entry[role] = resolved.get(role, "")
            entry[f"{role}_verified"] = False
            entry[f"{role}_source"] = "scraping" if role in resolved else ""

        discovered[lookup_name] = entry

    def _write_discovered_mapping(self, discovered: dict) -> None:
        """
        Store the resolved repository URLs which are not verified yet for
        manual review.

        Args:
            discovered: Resolved URLs of packages which are not verified.
        """
        if not discovered:
            return

        mapping_dir = path.join("data", "mapping")
        mapping_path = path.join(mapping_dir, f"{self.name.lower()}.json")
        makedirs(mapping_dir, exist_ok=True)
        with open(mapping_path, "w") as mapping_file:
            json.dump(discovered, mapping_file, indent=2, sort_keys=True)

        logger.warning(
            "Resolved repository URLs for %s packages which are not verified "
            "yet. Please review %s.",
            len(discovered), mapping_path
        )

    def generate(self, sbom_file: str, dir_name: Optional[str] = None) -> None:
        """
        Populate the minimal configuration from an SBOM file.

        Args:
            sbom_file: Path to the SBOM to generate the configuration from.
            dir_name: Name of the subdirectory for the data of this
                analysis run. If None, the SBOM's name is used.
        """
        # Attempt to parse the input file and save all repository links for
        # analysis to a configuration file.
        try:
            document: Document = spdx_parse_file(sbom_file)
            self.name = document.creation_info.name
            dir_name = dir_name or self.name.lower()
            self.perceval_dir += "/" + dir_name
            self.extract_dir += "/" + dir_name
            self.repo_dir += "/" + dir_name
            self.analysis_dir += "/" + dir_name

            # Resolving repository URLs by scraping is slow. Therefore, known
            # and validated URLs from previous runs are looked up in the tool's
            # static mapping first.
            static_mapping = self._load_package_mapping()

            # Resolved URLs of packages which no human verified yet are stored
            # and annotated separately for manual review.
            discovered = {}

            described = self._described_packages(document)

            packages = {}
            for p in document.packages:
                if p.spdx_id in described:
                    logger.info(
                        "Skipping %s, which is the system the SBOM describes "
                        "rather than a package of it.",
                        p.name
                    )
                    continue

                # Annotate each package with its package and git repository
                # URL, if possible. Repository identification is essential
                # to parse the commit history and calculate activity and code
                # quality metrics in the following steps.
                package_url = self._get_package_url(p)
                up_name = self._get_upstream_name_from_purl(p)
                lookup_name = up_name if up_name else p.name

                # Only the URLs which a human confirmed are reused from the
                # mapping.
                mapped = static_mapping.get(lookup_name, {})
                mapped_down = self._mapped_repo_url(mapped, "downstream")
                mapped_up = self._mapped_repo_url(mapped, "upstream")
                no_down = self._verified_absent(mapped, "downstream")
                no_up = self._verified_absent(mapped, "upstream")

                # Use verified URLs as confirmed literally.
                if (mapped_down is not None or no_down) and \
                        (mapped_up is not None or no_up):
                    downstream_repo = mapped_down
                    upstream_repo = mapped_up
                    if downstream_repo == upstream_repo:
                        upstream_repo = None

                    packages[p.spdx_id] = PackageInfo(
                        p.name,
                        p.version,
                        package_url,
                        downstream_repo=downstream_repo,
                        upstream_repo=upstream_repo
                    )
                    continue

                if mapped_down is not None:
                    downstream_repo = mapped_down
                elif no_down:
                    downstream_repo = None
                else:
                    downstream_repo = self._get_repository_url(p)
                upstream_repo = mapped_up

                if downstream_repo:
                    # Post-process URL if possible to ensure that the
                    # corresponding git repository can be cloned.
                    # Important: This is a best-effort approach.
                    if mapped_down is None:
                        downstream_repo = self._process_url(downstream_repo)

                    is_downstream = downstream_repo is not None and (
                        mapped_down is not None
                        or "salsa.debian" in downstream_repo
                        or "git.debian" in downstream_repo
                    )

                    if downstream_repo is None:
                        pass
                    elif is_downstream and no_up:
                        # The mapping documents that there is no upstream
                        # repository, so the package is Debian's own.
                        pass
                    elif is_downstream:
                        # Try to find the upstream repository from the Salsa
                        # project.
                        if upstream_repo is None:
                            upstream_repo = self._find_upstream_url_from_gitlab(
                                downstream_repo
                            )
                        if upstream_repo is not None:
                            if mapped_up is None:
                                upstream_repo = self._process_url(
                                    upstream_repo
                                )
                            if upstream_repo == downstream_repo:
                                upstream_repo = None
                        if upstream_repo is None and p.homepage:
                            upstream_repo = self._find_repo_url_from_homepage(
                                p.homepage
                            )

                        # Rust crates document their repository in the
                        # registry rather than in the Debian packaging.
                        if upstream_repo is None:
                            repo_url = self._find_upstream_url_from_crates_io(
                                p.name
                            )
                            if repo_url is not None:
                                upstream_repo = self._process_url(repo_url)

                        # Prevent the same repository from appearing as both
                        # upstream and downstream.
                        if upstream_repo is not None:
                            upstream_repo = self._process_url(upstream_repo) \
                                if isinstance(upstream_repo, str) \
                                   and upstream_repo != mapped_up \
                                   and not upstream_repo.endswith(".git") \
                                else upstream_repo
                            if upstream_repo == downstream_repo:
                                upstream_repo = None

                        if upstream_repo is None:
                            logger.info(
                                "Could not find an upstream repository URL "
                                "for %s.",
                                p.name
                            )
                    else:
                        # Not a Debian repository which already is the
                        # upstream.
                        if upstream_repo is None:
                            upstream_repo = downstream_repo
                        downstream_repo = None

                packages[p.spdx_id] = PackageInfo(
                    p.name,
                    p.version,
                    package_url,
                    downstream_repo=downstream_repo,
                    upstream_repo=upstream_repo
                )

                self._record_resolved_urls(
                    discovered, static_mapping, lookup_name,
                    downstream_repo, upstream_repo
                )

            self.packages = packages
            self._write_discovered_mapping(discovered)
        except SPDXParsingError:
            logger.exception("Failed to parse SPDX file.")

    @classmethod
    def from_yaml(cls, conf_file: str) -> "Config":
        """
        Load configuration from an existing YAML file.
        """
        with open(conf_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            data["packages"] = {
                k: PackageInfo(**v) for k, v in data["packages"].items()
            }
        return cls(**data)

    def to_yaml(self, conf_file: str) -> None:
        """
        Export configuration to a YAML file.
        """
        with open(conf_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                asdict(self),
                f,
                sort_keys=False,
                allow_unicode=True
            )
