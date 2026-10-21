import csv
import logging
import re

from datetime import datetime
from git import Repo, GitCommandError
from git.exc import BadName, GitError
from os import makedirs, path
from pandas import concat, DataFrame
from perceval.backends.core.git import Git
from perceval.errors import RepositoryError
from shutil import rmtree
from typing import Optional

from sbom_analysis.config.config import PackageInfo, monorepo_downstreams
from sbom_analysis.util import (analysis_dir_name, checkout_version,
                                repo_dir_name, safe_read_commits,
                                safe_read_csv)

logger = logging.getLogger(__name__)

# In mono repositories such as debcargo-conf, ecosystem prefixes may be
# used to identify packages, e.g. "rust-nettle" for "nettle".
ECOSYSTEM_PREFIXES = ("rust-",)


class GitExtractor:
    """
    Data extractor for git repositories defined in the configuration file.
    """

    @staticmethod
    def _remote_ref_exists(
            remote_branches: set[str],
            remote_tags: set[str],
            v: str,
            exact: bool = True
    ) -> str | None:
        """
        Check if a branch or tag for a given version string exists in the
        pre-fetched sets of remote refs.

        Refs are compared exactly unless the caller allows a prefix match, so
        that an imprecise version pattern cannot claim a reference which a more
        precise pattern describes exactly.

        Args:
            remote_branches: Set of remote branch names (without refs/heads/).
            remote_tags: Set of remote tag names (without refs/tags/).
            v: Version string to check for.
            exact: Whether only a ref of exactly that name is accepted.

        Returns:
            The matching ref name if found, None otherwise.
        """
        if v in remote_branches or v in remote_tags:
            return v

        if exact:
            return None

        # The prefix must end at the version boundary. For instance, 3.1 may
        # match 3.1-rc1 etc., but not 3.10.
        for refs in (remote_branches, remote_tags):
            matches = [
                r for r in refs
                if r.startswith(v) and not re.match(r"[._]?\d", r[len(v):])
            ]
            if matches:
                return min(matches, key=lambda r: (len(r), r))

        return None

    @staticmethod
    def _get_hash_by_date(r: Repo, v: str) -> str | None:
        """
        For date-like version names, try to find the latest commit hash at
        that date.

        Args:
            r: Git repository object.
            v: Version string to attempt to parse as date.

        Returns:
            The commit hash if found, None otherwise.
        """
        try:
            if len(v) == 6:
                date = datetime.strptime(v, "%y%m%d")
            elif len(v) == 8:
                date = datetime.strptime(v, "%Y%m%d")
            else:
                return None
        except ValueError:
            return None

        for c in r.iter_commits():
            if c.committed_datetime.date() <= date.date():
                return c.hexsha
        return None

    def _test_checkout(
            self,
            repo_path: str,
            repo_url: str,
            package_id: str,
            package_version: str,
            package_name: str,
            repo_type: str,
            package_dir: str | None = None
    ) -> str | None:
        """
        Try to check out the correct version of the repository to ensure that
        analysis results match.

        Args:
            repo_path: Path to the local repository.
            repo_url: Remote repository URL.
            package_id: Package identifier from the SBOM.
            package_version: Package version from the SBOM.
            package_name: Package name from the SBOM.
            repo_type: Type of repository to check out (down or up).
            package_dir: Package directory in a mono repository, None otherwise.

        Returns:
            The branch, tag, or commit hash that was checked out if
            successful, None otherwise.
        """
        if package_version is None:
            return None

        # Get the cloned repository.
        try:
            repo = Repo(repo_path)
            repo_name = repo_url.split("/")[-1].removesuffix(".git")
        except GitCommandError as e:
            logger.debug(e, exc_info=True)
            return None

        # Build ref sets once here to avoid re-fetching them on every call.
        try:
            remote_branches = {
                ref.remote_head for ref in repo.remotes.origin.refs
            }
            remote_branches |= {
                b.removeprefix("refs/heads/") for b in remote_branches
            }
            remote_tags = {
                tag.name.removeprefix("refs/tags/") for tag in repo.tags
            }
        except Exception as e:
            logger.debug("Could not fetch remote refs for %s: %s",
                         package_id, e)
            remote_branches = set()
            remote_tags = set()

        # Strip epoch prefix (e.g. "1:2.39.3-10" → "2.39.3-10") and binary
        # suffix (e.g. "+b1"), so all patterns can reuse the cleaned parts.
        v_no_epoch   = package_version.split(":")[-1]
        v_no_binnmu  = package_version.split("+b")[0]
        v_upstream   = v_no_epoch.split("-")[0]           # e.g. "2.39.3"
        v_no_dfsg    = re.sub(r"[.+]dfsg.*", "", v_upstream)  # e.g. "1.3"
        v_no_really  = package_version.split("really")[-1]

        v_patterns = [
            # Salsa Debian Downstream conventions.
            package_version,
            v_no_binnmu,
            v_no_epoch,
            v_no_really,
            "debian/" + package_version,
            "debian/" + v_no_binnmu,
            "debian/" + v_no_epoch,
            "debian/" + v_no_really,
            "debian/" + package_version.replace(":", "%"),
            "debian/" + package_version.replace("~", "_"),
            "debian/" + package_version.split("really")[-1],
            "debian/" + package_version.split("+")[0],
            "debian/" + package_version.replace(":", "%").split("+")[0],
            "debian/" + package_version.split(":")[-1],
            package_version.split(":")[-1].split("-")[0].removesuffix(".dfsg"),
            package_version.split("-")[0],
            package_version.split("-")[0].replace(".", "-"),
            "debian/" + v_no_epoch.split("+")[0],
            "debian/" + v_no_epoch.split("+")[0].split("-")[0],
            "debian/" + repo_name + "-" + package_version,
            "debian/" + repo_name + "-" + v_no_epoch,
            # Tags of versions which are no longer packaged are moved to the
            # archive namespace. Older releases are therefore often only tagged
            # there.
            "archive/debian/" + package_version,
            "archive/debian/" + v_no_binnmu,
            "archive/debian/" + v_no_epoch,
            "archive/debian/" + v_no_really,
            "archive/debian/" + package_version.replace(":", "%"),
            "archive/debian/" + package_version.replace("~", "_"),
            "archive/debian/" + package_version.split("+")[0],
            "archive/debian/" + v_no_epoch.split("+")[0],
            "archive/debian/" + v_no_epoch.split("+")[0].split("-")[0],
            # Upstream conventions, e.g. from GitHub.
            v_upstream,
            v_no_dfsg,
            package_version.split("+")[0].split("-")[0],
            package_version.replace("-", "."),
            package_version.replace("-", "_"),
            repo_name + "-" + package_version,
            repo_name + "-" + package_version.split("-")[0].replace(".", "-"),
            repo_name + "-" + v_upstream,
            package_name + "-" + v_upstream,
            "v" + package_version,
            "v" + package_version.split("-")[0],
            "v" + package_version.split("-")[0].replace(":", "."),
            "v" + package_version.split("-")[0].replace(".", "_"),
            "v" + package_version.split(":")[-1],
            "v" + package_version.split(":")[-1].split("-")[0],
            "v" + v_no_epoch,
            "v" + v_upstream,
            "v" + v_upstream.replace(".", "_"),
            "v" + v_no_dfsg,
            "v" + package_version.replace("-", "."),
            "v" + v_no_really,
            "v" + v_no_really.split("+")[0],
            "v" + v_no_really.split("-")[0],
            "v" + package_version.split("+")[0],
            "v" + package_version.split("really")[-1],
            "v" + package_version.split("really")[-1].split("+")[0],
            "v" + package_version.split("really")[-1].split("-")[0],
            # Special prefix conventions.
            "version-" + package_version.split("-")[0],
            "R_" + package_version.replace(".", "_"),
            "R_" + package_version.replace(".", "_").split("-")[0],
            "R_" + v_upstream.replace(".", "_"),
            repo_name + "-" + package_version.split("-")[0],
            package_version.rsplit(".", 1)[0] + ".x",
            package_version.split(":")[-1].split("-")[0],
            "stable/" + v_upstream,
            "stable/" + v_no_epoch.split("-")[0],
            "release/" + v_upstream,
            "release/" + v_upstream + "/master",
            "t" + package_version.split(".")[-1].split("-")[0],
            package_version.split("~")[0],
            package_version.split("+deb")[0],
            v_no_dfsg,
            "".join(p + "." if len(p) > 1 else "0" + p + "."
                    for p in package_version.split("+")[0].split(".")
                    ).removesuffix("."),
            ".".join(
                p.lstrip("0") or "0"
                for p in v_upstream.split(".")
            ),
            v_upstream.rsplit(".", 1)[0] + ".x",
            repo_name.upper() + "_REL_ENG_" +
            package_version.split("-")[0].replace(".", "_"),
            "Linux-PAM-" + package_version.split("-")[0].replace(".", "_"),
            "OpenSSL" + "_" + package_version.split("-")[0].replace(".", "_")
        ]

        # Some patterns may yield duplicate strings. Deduplicate these
        # while preserving order so more specific patterns are
        # tried first.
        seen = set()
        v_patterns_dedup = []
        for p in v_patterns:
            if p and p not in seen:
                seen.add(p)
                v_patterns_dedup.append(p)

        # Fall back to approximate matching only if the exact matching failed.
        for exact in (True, False):
            for ver in v_patterns_dedup:
                ref = self._remote_ref_exists(
                    remote_branches, remote_tags, ver, exact
                )
                if ref is not None:
                    return ref

        # If no tag is found, search for the version string in the history of
        # debian/changelog via git log -S (pickaxe search). This is very
        # reliable for Debian packages even when tags are missing.
        #
        # Use git log -S (pickaxe search) which is natively optimized and
        # extremely fast for searching commit histories.
        changelog = "debian/changelog"
        if package_dir:
            changelog = package_dir.strip("/") + "/" + changelog
        try:
            search_version          = v_no_binnmu
            search_version_no_epoch = v_no_epoch.split("+")[0]

            for pattern in [
                f"({search_version})",
                f"({search_version_no_epoch})",
                f" {search_version} ",
                f" {search_version_no_epoch} ",
            ]:
                commit_hash = repo.git.log(
                    "--format=%H", "-n", "1",
                    "-S", pattern,
                    "--", changelog
                ).strip()
                if commit_hash:
                    logger.info(
                        "Changelog Detective found commit %s for version %s "
                        "of %s.", commit_hash, package_version, package_id
                    )
                    return commit_hash
        except Exception as e:
            logger.debug("Changelog Detective failed for %s: %s",
                         package_id, e)

        # For packaging repositories with no version tag, fall back to the
        # standard Debian branch names.
        if repo_type == "down" and not package_dir:
            for b in ["debian/latest", "debian/master", "master"]:
                ref = self._remote_ref_exists(remote_branches, remote_tags, b)
                if ref is not None:
                    logger.info("Using fallback branch %s for %s.", b,
                                package_id)
                    return ref

        # Scan the full commit history with commit messages, as some
        # repositories note versions there.
        v_keywords = [
            "release", "version", "packaging", "change log", "changelog",
            "changes", "document", "prepare", "merge", "import", "update"
        ]
        s_v_patterns = [
            package_version,
            package_version.replace("-", " patch "),
            package_name + "-" + package_version.replace("-", " patch "),
        ]
        p_name = package_name.removeprefix("rust-")

        strict_match  = None
        loose_match   = None
        pattern_match = None

        for commit in repo.iter_commits():
            if p_name in commit.summary.lower() and \
                any(k in commit.summary.lower() for k in v_keywords) and \
                any(v in commit.summary for v in s_v_patterns):
                logger.debug(f"Found latest commit {commit.hexsha} mentioning "
                             f"package name {p_name} and version "
                             f"{package_version} of package {package_id} "
                             f"directly in the commit summary.")
                return commit.hexsha

            # Stop as soon as we have the strictest match.
            if strict_match is not None:
                break

        for match in [strict_match, loose_match, pattern_match]:
            if match is not None:
                logger.debug(
                    "Found commit %s mentioning version %s of %s in commit "
                    "summary.", match, package_version, package_id
                )
                return match

        # Fall back to the version date.
        if package_version.isdigit():
            commit_hash = self._get_hash_by_date(repo, package_version)
            if commit_hash is not None:
                return commit_hash

        # Last resort: scan commit summaries for any of the version patterns
        # (not just the exact version string).
        version_tokens = [
            # Ensure the version is matched as a whole, e.g. 3.1 but not 13.1.
            re.compile(r"(?<![\w.])" + re.escape(v.lower()) + r"(?![\w]|\.\d)")
            for v in v_patterns_dedup
            # Ensure that the pattern looks like a version (digit, separator,
            # digit).
            if re.search(r"\d[._]\d", v)
        ]
        for commit in repo.iter_commits():
            summary_lower = commit.summary.lower()
            if any(k in summary_lower for k in v_keywords) and \
                    any(t.search(summary_lower) for t in version_tokens):
                logger.debug(
                    "Found commit %s with similar version pattern for %s.",
                    commit.hexsha, package_id
                )
                return commit.hexsha

        # As a last option, we try to find only the version regardless of
        # specific keywords.
        p_replacement = package_version.rsplit(".", 1)
        p_replacement = " patch ".join(p_replacement).split("-")[0]
        for commit in repo.iter_commits():
            if package_name + "-" + p_replacement in commit.summary.lower():
                return commit.hexsha

        return None

    @staticmethod
    def _directory_candidates(
            package_name: str,
            upstream_repo: Optional[str] = None
    ) -> list[str]:
        """
        Get name candidates of the directory of a package in a mono repository.

        Args:
            package_name: Name of the package.
            upstream_repo: URL of the upstream repository.

        Returns:
            The candidate names, most specific first.
        """
        # The package name itself.
        candidates = [package_name]
        # Names with ecosystem prefix.
        for prefix in ECOSYSTEM_PREFIXES:
            if package_name.startswith(prefix):
                candidates.append(package_name[len(prefix):])
        if upstream_repo is not None:
            # The project name in the upstream URL.
            candidates.append(
                upstream_repo.rstrip("/").rsplit("/", 1)[-1]
                .removesuffix(".git")
            )
        return candidates

    @staticmethod
    def _package_dir_in_repo(
            repo_path: str,
            package_name: str,
            upstream_repo: Optional[str] = None
    ) -> Optional[str]:
        """
        Search the directory of a package in the cloned tree of a downstream
        mono repository.

        Args:
            repo_path: Path to the cloned repository.
            package_name: Name of the package.
            upstream_repo: URL of the upstream repository.

        Returns:
            The directory path, or None.
        """
        try:
            repo = Repo(repo_path)
            # Get directory candidates.
            tops = repo.git.ls_tree("-d", "--name-only", "HEAD").splitlines()
            for candidate in GitExtractor._directory_candidates(
                    package_name, upstream_repo
            ):
                for top in tops:
                    # Ensure that the candidate actually exists in the
                    # repository.
                    directory = top + "/" + candidate
                    if repo.git.ls_tree("-d", "--name-only", "HEAD",
                                        directory).strip() == directory:
                        return directory
        except GitError as e:
            logger.debug(e, exc_info=True)
        return None

    @staticmethod
    def _downstream_path(
            package_name: str,
            files_path: str,
            upstream_repo: Optional[str] = None
    ) -> Optional[str]:
        """
        Find the directory of a specific package inside a downstream mono
        repository.

        Directories are usually named after the project that is packaged,
        without the prefix of its ecosystem, or the name of its upstream
        repository.

        Args:
            package_name: Name of the package.
            files_path: Path to the files of the downstream repository.
            upstream_repo: URL of the upstream repository, whose name the
                directory carries where the package is named differently.

        Returns:
            The directory, or None.
        """
        files = safe_read_csv(files_path)
        if files is None or "file_path" not in files:
            return None

        # Collect candidate directories for the package.
        # E.g. debcargo-conf holds one per crate in src/, as in "src/nettle".
        parts = files["file_path"].astype(str).str.split("/")
        directories = set(
            parts[parts.str.len() > 1].str[:2].str.join("/")
        )
        candidates = GitExtractor._directory_candidates(
            package_name, upstream_repo
        )
        for candidate in candidates:
            for directory in directories:
                if directory.split("/")[-1] == candidate:
                    return directory

        logger.warning(
            "No directory of package %s in its monorepo. Commits "
            "cannot be separated from those of the other packages.",
            package_name
        )
        return None

    @staticmethod
    def _commits_of_path(
            commits: DataFrame | None,
            files: DataFrame,
            downstream_path: str
    ) -> tuple[DataFrame | None, DataFrame]:
        """
        Filter commits changing the specific package directory in a mono
        repository.

        Args:
            commits: The commits of the downstream repository.
            files: The files those commits touch.
            downstream_path: Directory of the package in the repository.

        Returns:
            The commits and the files which belong to the package.
        """
        if commits is None:
            return commits, files

        paths = files["file_path"].astype(str)
        touched = files[paths.str.startswith(downstream_path + "/")]
        kept = commits[commits["commit_hash"].isin(touched["commit_hash"])]
        logger.info(
            "%d of %d commits of the mono repository changed %s.",
            len(kept), len(commits), downstream_path
        )
        return kept, touched

    @staticmethod
    def _unify_commits(
            res_dirs: dict[str, str],
            package_path: str,
            downstream_path: Optional[str] = None
    ) -> None:
        """
        Unify commits and files across downstream and upstream repositories to
        remove duplicates.

        Args:
            res_dirs: Paths to the data extracted per repository.
            package_path: Path to store the unified data of the package.
            downstream_path: Directory of the package inside its downstream
                repository, where that repository holds several packages. The
                commits which touch no file of it belong to another package
                and are left out.
        """
        down_dir = res_dirs.get("down")
        up_dir = res_dirs.get("up")

        commits_down = safe_read_commits(
            path.join(down_dir, f"down_commits.csv")
        ) if down_dir else None
        commits_up = safe_read_commits(
            path.join(up_dir, f"up_commits.csv")
        ) if up_dir else None
        files_down = safe_read_csv(
            path.join(down_dir, f"down_files.csv")
        ) if down_dir else None
        files_up = safe_read_csv(
            path.join(up_dir, f"up_files.csv")
        ) if up_dir else None
        if commits_down is None and commits_up is None:
            # If no commits were found, no files were found either.
            return

        if downstream_path is not None and files_down is not None:
            commits_down, files_down = GitExtractor._commits_of_path(
                commits_down, files_down, downstream_path
            )

        # Remove duplicate commits and files. As file paths are relative when
        # extracted by Perceval, there is no need to process them.
        if commits_down is not None and commits_up is not None:
            commits = concat([commits_down, commits_up])
            commits.drop_duplicates(inplace=True)
        elif commits_down is not None:
            commits = commits_down
        else:
            commits = commits_up

        # Ensure to use the same date format as the original git log.
        commits["author_date"] = commits["author_date"].dt.strftime(
            "%a %b %d %H:%M:%S %Y %z"
        )
        commits["committer_date"] = commits["committer_date"].dt.strftime(
            "%a %b %d %H:%M:%S %Y %z"
        )
        makedirs(package_path, exist_ok=True)
        commits.to_csv(path.join(package_path, f"commits.csv"), index=False)

        if files_down is not None or files_up is not None:
            files = concat([files_down, files_up])
            files.drop_duplicates(inplace=True)
            files.to_csv(path.join(package_path, f"files.csv"), index=False)

    @staticmethod
    def _is_cloned(repo_path: str) -> bool:
        """
        Check whether a repository was cloned completely.

        An interrupted clone leaves a repository without any reference behind,
        which cannot be used and would fail.

        Args:
            repo_path: Path to the local repository.

        Returns:
            True if the repository can be used, False otherwise.
        """
        if not path.isdir(path.join(repo_path, ".git")):
            return False

        try:
            return len(Repo(repo_path).references) > 0
        except (GitError, ValueError) as e:
            logger.debug(e, exc_info=True)
            return False

    @staticmethod
    def _fetch_repo(repo_url: str, repo_path: str) -> bool:
        """
        Clone a repository, or fetch the latest commits if it was already
        cloned.

        Several packages can be managed in the same repository, so the
        repository is fetched once instead of once per package. Fetching is
        the only step requiring network access.

        Args:
            repo_url: Remote repository URL.
            repo_path: Path to clone the repository to.

        Returns:
            True if the repository is available locally, False otherwise.
        """
        # Git asks for credentials if a repository is private or does not
        # exist, which blocks the run while waiting for an input which
        # cannot be provided.
        # Disabling the prompt turns such a repository into a reported error.
        git_env = {"GIT_TERMINAL_PROMPT": "0"}

        # Discard the remains of an interrupted clone to ensure that the
        # repository is cloned again instead of failing.
        cloned = GitExtractor._is_cloned(repo_path)
        if path.exists(repo_path) and not cloned:
            logger.warning(
                "Repository %s was not cloned completely. Removing.",
                repo_path
            )
            rmtree(repo_path, ignore_errors=True)

        if not cloned:
            try:
                Repo.clone_from(repo_url, repo_path, env=git_env)
                return True
            except GitError:
                # The repository is left out of all metrics, so the reason is
                # reported with the warning instead of the debug output.
                logger.warning(
                    "Could not clone %s with git. Ignoring.",
                    repo_url,
                    exc_info=True
                )
                return False

        try:
            repo = Repo(repo_path)
            repo.git.update_environment(**git_env)

            # To ensure that we are working on the latest version of the
            # repository before searching for checkout points, checkout the
            # main branch and fetch the latest commits.
            remote_info = repo.git.remote("show", "origin")
            match = re.search(r"HEAD branch: (.*)", remote_info)
            if match:
                default_branch = match.group(1)
                checkout_version(repo, default_branch)
            repo.remotes.origin.fetch()
            return True
        except Exception:
            logger.warning(
                "Could not handle the repository %s with git. Ignoring.",
                repo_url,
                exc_info=True
            )
            return False

    def clone(
            self,
            packages: dict[str, PackageInfo],
            repo_dir: str
    ) -> dict[str, PackageInfo]:
        """
        Clone the relevant git repositories for analysis and persist the
        resolved checkout points back into the package info objects.

        Returns the updated packages dict with downstream_checkout and
        upstream_checkout populated.

        Args:
            packages: Dictionary of package identifiers and their metadata.
            repo_dir: Directory where the git repositories are cloned.

        Returns:
            Updated packages dict with checkout points filled in.
        """
        makedirs(repo_dir, exist_ok=True)

        # Collect the repositories of all packages. Multiple packages can be
        # managed in the same repository, which is fetched only once.
        repos = {}
        for package_info in packages.values():
            urls = {
                "down": package_info.downstream_repo,
                "up":   package_info.upstream_repo
            }
            for repo_type, repo_url in urls.items():
                if repo_url is None:
                    continue

                repo_name = repo_dir_name(repo_url, repo_type)
                if repo_name is None:
                    continue

                repos.setdefault(
                    repo_name, (repo_url, path.join(repo_dir, repo_name))
                )

        # Clone or update all repositories defined in the configuration file.
        fetched = set()
        for n, (repo_name, repo) in enumerate(repos.items(), start=1):
            repo_url, repo_path = repo
            logger.info(
                "Fetching repository %s (%s of %s).",
                repo_url, n, len(repos)
            )
            if self._fetch_repo(repo_url, repo_path):
                fetched.add(repo_name)

        # Identify the correct version of each package's repositories to
        # ensure that their state matches the vulnerability scan. If no
        # matching checkout point can be found, we ignore the repository to
        # avoid misalignment and incorrect results.
        monorepos = monorepo_downstreams(packages)
        for package_id, package_info in packages.items():
            urls = {
                "down": package_info.downstream_repo,
                "up":   package_info.upstream_repo
            }
            for repo_type, repo_url in urls.items():
                if repo_url is None:
                    continue

                repo_name = repo_dir_name(repo_url, repo_type)
                if repo_name is None or repo_name not in fetched:
                    continue

                package_dir = None
                if repo_type == "down" and repo_url in monorepos:
                    # Get the downstream directory path in a mono repository.
                    package_dir = package_info.downstream_path or \
                        self._package_dir_in_repo(
                            repos[repo_name][1], package_info.name,
                            package_info.upstream_repo
                        )
                    package_info.downstream_path = package_dir

                checkout = self._test_checkout(
                    repos[repo_name][1], repo_url,
                    package_id, package_info.version, package_info.name,
                    repo_type, package_dir=package_dir
                )
                if repo_type == "down":
                    if checkout is None:
                        logger.warning(
                            "Could not find a matching checkout point for "
                            "%s's downstream repository.", package_id
                        )
                    else:
                        package_info.downstream_checkout = checkout
                else:
                    if checkout is None:
                        logger.warning(
                            "Could not find a matching checkout point for "
                            "%s's upstream repository. Ignoring.", package_id
                        )
                    else:
                        package_info.upstream_checkout = checkout
            packages[package_id] = package_info
        return packages

    def _extract_repo(
            self,
            repo_path: str,
            perceval_path: str,
            checkout: str,
            res_path: str,
            repo_type: str
    ) -> None:
        """
        Extract and store the commits of one repository version.

        Perceval parses the whole git log on every call, so packages sharing a
        repository version are extracted once instead of once per package.

        Args:
            repo_path: Path to the cloned repository.
            perceval_path: Path to the repository mirror of perceval.
            checkout: Branch, tag or commit to extract the history up to.
            res_path: Path to store the extracted tables.
            repo_type: Type of repository to extract (down or up).
        """
        makedirs(res_path, exist_ok=True)
        commit_path = path.join(res_path, f"{repo_type}_commits.csv")
        file_path = path.join(res_path, f"{repo_type}_files.csv")

        # Determine perceval analysis time frame.
        try:
            perceval_repo = Git(uri=repo_path, gitpath=perceval_path)
            git_repo = Repo(repo_path)

            # Resolve the version to its commit date without checking it
            # out, as perceval reads the git log from its own mirror.
            reference_date = git_repo.commit(checkout).committed_datetime

            # Extract the git log with perceval and parse relevant
            # information into tables.
            try:
                git_log = perceval_repo.fetch(
                    to_date=reference_date,
                    branches=None # all branches
                )

                with open(
                        commit_path,
                        "w",
                        newline="",
                        encoding="utf-8",
                        errors="replace"
                ) as commit_table, \
                        open(
                            file_path,
                            "w",
                            newline="",
                            encoding="utf-8",
                            errors="replace"
                        ) as file_table:
                    commit_cols = [
                        "commit_hash",
                        "commit_message",
                        "is_merge",
                        "author",
                        "author_date",
                        "committer",
                        "committer_date",
                        "added",
                        "removed"
                    ]
                    commit_writer = csv.DictWriter(
                        commit_table, fieldnames=commit_cols
                    )
                    commit_writer.writeheader()
                    file_cols = [
                        "commit_hash",
                        "file_path",
                        "action",
                        "added",
                        "removed"
                    ]
                    file_writer = csv.DictWriter(
                        file_table, fieldnames=file_cols
                    )
                    file_writer.writeheader()

                    for commit in git_log:
                        # Extract file statistics per commit.
                        added_sum = 0
                        removed_sum = 0
                        message = commit["data"]["message"] if \
                            "message" in commit["data"] else ""

                        # Perceval does not report merges directly, but
                        # always lists the parents of a commit. Commits
                        # with more than one parent are merges.
                        is_merge = len(commit["data"]["parents"]) > 1

                        for file_change in commit["data"]["files"]:
                            action = file_change["action"] if \
                                "action" in file_change else "-"
                            added = file_change["added"] if \
                                "added" in file_change else 0
                            removed = file_change["removed"] if \
                                "removed" in file_change else 0

                            file_entry = {
                                "commit_hash": commit["data"]["commit"],
                                "file_path": file_change["file"],
                                "action": action,
                                "added": added,
                                "removed": removed
                            }
                            file_writer.writerow(file_entry)

                            if added != "-":
                                added_sum += int(added)
                            if removed != "-":
                                removed_sum += int(removed)

                        # Aggregate commit information.
                        commit_entry = {
                            "commit_hash": commit["data"]["commit"],
                            "commit_message": message,
                            "is_merge": is_merge,
                            "author": commit["data"]["Author"],
                            "author_date": commit["data"]["AuthorDate"],
                            "committer": commit["data"]["Commit"],
                            "committer_date": commit["data"]["CommitDate"],
                            "added": added_sum,
                            "removed": removed_sum
                        }
                        commit_writer.writerow(commit_entry)

            except RepositoryError:
                logger.warning(
                    "Could not parse %s with perceval. Check config.",
                    repo_path,
                    exc_info=True
                )
                # Remove the created directory if a parsing error occurred
                # to avoid misinterpretation as repository with no commits
                # in the analysed time frame.
                rmtree(res_path, ignore_errors=True)

        except (GitError, BadName):
            logger.warning(
                "Could not find version %s of the repository at %s. Ignoring.",
                checkout,
                repo_path,
                exc_info=True
            )

    def extract(
            self,
            packages: dict[str, PackageInfo],
            repo_dir: str,
            perceval_dir: str,
            extract_dir: str,
            history_months: int
    ) -> None:
        """
        Extract and store commits from the git repositories. We use local
        clones to ensure that all subsequent analyses and tools refer to the
        same repository state.

        Args:
            packages: Dictionary of package identifiers and their metadata.
            repo_dir: Directory where the git repositories are cloned.
            perceval_dir: Directory where perceval stores its data.
            extract_dir: Directory where the extracted data is stored.
            history_months: Number of months to look back for commits.
        """
        repo_versions = {}
        package_dirs = {}

        for package_id, package_info in packages.items():
            urls = {
                "down": package_info.downstream_repo,
                "up":   package_info.upstream_repo
            }
            checkouts = {
                "down": package_info.downstream_checkout,
                "up":   package_info.upstream_checkout
            }

            res_dirs = {}
            for repo_type, repo_url in urls.items():
                if repo_url is None or checkouts[repo_type] is None:
                    continue

                repo_name = repo_dir_name(repo_url, repo_type)
                if repo_name is None:
                    continue

                # If the configuration specifies the version, e.g. determined
                # from a previous run or added manually, the repository could
                # be missing if the clone failed.
                if not path.isdir(path.join(repo_dir, repo_name, ".git")):
                    logger.warning(
                        "Could not find repository %s to extract. Ignoring.",
                        repo_name
                    )
                    continue

                res_name = analysis_dir_name(repo_name, checkouts[repo_type])
                res_dirs[repo_type] = path.join(extract_dir, "repos", res_name)
                repo_versions.setdefault(res_name, (
                    repo_type,
                    path.join(repo_dir, repo_name),
                    # Perceval mirrors the repository to read its git log.
                    path.join(perceval_dir, repo_name),
                    checkouts[repo_type]
                ))

            package_dirs[package_info.name] = res_dirs

        # Extract the git log of each repository version.
        for n, (res_name, version) in enumerate(
                repo_versions.items(), start=1
        ):
            repo_type, repo_path, perceval_path, checkout = version
            logger.info(
                "Extracting repository %s (%s of %s)...",
                res_name, n, len(repo_versions)
            )
            self._extract_repo(
                repo_path,
                perceval_path,
                checkout,
                path.join(extract_dir, "repos", res_name),
                repo_type
            )

        # In mono repositories, narrow down commits to the specific package
        # directory.
        monorepos = monorepo_downstreams(packages)
        packages_by_name = {
            package_info.name: package_info
            for package_info in packages.values()
        }

        # Unify commits and files across downstream and upstream
        # repositories to remove duplicate references.
        for package_name, res_dirs in package_dirs.items():
            package_info = packages_by_name.get(package_name)
            downstream_path = None
            if package_info is not None \
                    and package_info.downstream_repo in monorepos:
                downstream_path = package_info.downstream_path
                if downstream_path is None and "down" in res_dirs:
                    downstream_path = self._downstream_path(
                        package_name,
                        path.join(res_dirs["down"], "down_files.csv"),
                        package_info.upstream_repo
                    )
                    package_info.downstream_path = downstream_path
            self._unify_commits(
                res_dirs, path.join(extract_dir, package_name),
                downstream_path
            )
