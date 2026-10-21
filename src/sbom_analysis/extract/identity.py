import logging
import re

from os import listdir, path
from pandas import DataFrame, read_csv

logger = logging.getLogger(__name__)


class IdentityHandler:
    """
    Handler for developer identities..
    """

    @staticmethod
    def _extract_email(dev: str) -> str | None:
        """
        Helper function to extract the e-mail address of a developer and
        filter out shared e-mail addresses.

        Args:
            dev: Single name and e-mail address of the developer.

        Returns:
            The e-mail address if it likely identifies a single developer,
            None otherwise.
        """
        m = re.search(r"<(.*?)>", dev)
        if not m:
            return None
        email = m.group(1).strip()

        # Exclude special e-mail addresses shared by developers.
        # This handles special cases such as "<Unknown>" and
        # "noreply@github.com" for commits created via its web interface (or
        # configured by developers).
        exclude_patterns = r"^(?:-|\(none\)|none|unknown|nobody|null|n/a|" \
                           r"noreply@github\.com|.*@localhost)$"
        if len(email) <= 1 or re.match(exclude_patterns, email, re.IGNORECASE):
            return None
        return email

    @staticmethod
    def _extract_github_username(dev: str) -> str | None:
        """
        Helper function to extract a GitHub username from a noreply e-mail
        address.

        Args:
            dev: Single name and e-mail address of the developer.

        Returns:
            The GitHub username if in the GitHub noreply e-mail address, None
            otherwise.
        """
        # GitHub noreply addresses are either <username@users.noreply.github.
        # com> or <ID+username@users.noreply.github.com>. Exclude the
        # characters surrounding an address, as the local part would otherwise
        # be matched together with the preceding developer name.
        pattern = re.compile(
            r"(?:\d+\+)?([^@<>\s]+)@users\.noreply\.github\.com"
        )
        m = pattern.search(dev)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _extract_name(dev: str) -> str | None:
        """
        Helper function to extract the name of a developer and
        filter out non-developer names.

        Args:
            dev: Single name and e-mail address of the developer.

        Returns:
            The name if it likely identifies a single developer, None
            otherwise.
        """
        name = dev.split("<")[0].strip()

        # Do not match identities named unknown, which might originate from an
        # API issue.
        if not name or name.lower() == "unknown":
            return None
        return name

    def _group_ids(self, unique_ids: set[str]) -> dict[str, str]:
        """
        Helper function to merge the diverging identities of each developer.

        Two identities belong to the same developer if they share the e-mail
        address, the GitHub username, or the full name.

        Args:
            unique_ids: Distinct observed identities.

        Returns:
            A dictionary with the observed identities as keys and the merged
            identity of the corresponding developer as values.
        """
        # Union-find over the identities. Parent keep track of the groups.
        parent = {dev: dev for dev in unique_ids}

        def find(dev: str) -> str:
            while parent[dev] != dev:
                parent[dev] = parent[parent[dev]]
                dev = parent[dev]
            return dev

        def union(dev_1: str, dev_2: str) -> None:
            root_1, root_2 = find(dev_1), find(dev_2)
            if root_1 != root_2:
                parent[root_2] = root_1

        first_seen: dict[tuple[str, str], str] = {}
        for dev in sorted(unique_ids):
            keys = (
                ("email", self._extract_email(dev)),
                ("github", self._extract_github_username(dev)),
                ("name", self._extract_name(dev))
            )
            for key in keys:
                if key[1] is None:
                    continue
                if key in first_seen:
                    union(first_seen[key], dev)
                else:
                    first_seen[key] = dev

        # Represent each group as a list of identities, which are then joined
        # to one identity per developer.
        members: dict[str, list[str]] = {}
        for dev in unique_ids:
            members.setdefault(find(dev), []).append(dev)

        merged = {}
        for group in members.values():
            # Create the merged identity string per developer.
            identity = " | ".join(sorted(group))
            for dev in group:
                merged[dev] = identity
        return merged

    def _replace_ids(
            self,
            commits_table: DataFrame
    ) -> tuple[DataFrame, DataFrame]:
        """
        Helper function to replace possibly diverging identities in the commits
        table.

        Args:
            commits_table: Commits table with potentially diverging identities.

        Returns:
            Identity table with unique person identities and the commits table
            with merged identities.
        """
        # Keep the original identities observed in the commits, as merging
        # overwrites them.
        # If the original identities are already present from a previous run,
        # we keep those, as author and committer may then already have been
        # merged.
        if "original_author" not in commits_table:
            commits_table["original_author"] = commits_table["author"]
            commits_table["original_committer"] = commits_table["committer"]
        observed = commits_table[["original_author", "original_committer"]]

        # Merge the identities of the developers.
        merged = self._group_ids(set(observed.stack()))
        identities = DataFrame({"identity": sorted(set(merged.values()))})

        # Replace the identities in the commits table with the merged
        # identities.
        commits_table["author"] = observed["original_author"].map(merged)
        commits_table["committer"] = observed["original_committer"].map(merged)
        return identities, commits_table

    def merge(self, extract_dir: str) -> None:
        """
        Merge developer identities using different names and e-mail addresses
        in the extracted data.

        Args:
            extract_dir: Directory with the extracted data.
        """
        packages = sorted(listdir(extract_dir))
        for n, package in enumerate(packages, start=1):
            commits_path = path.join(extract_dir, package, "commits.csv")
            if not path.exists(commits_path):
                continue
            commits_table = read_csv(commits_path)
            if len(commits_table) == 0:
                continue

            identities, commits_merged = self._replace_ids(commits_table)
            logger.info(
                "Merged the identities of %s (%d of %d).",
                package, n, len(packages)
            )
            identities.to_csv(
                path.join(extract_dir, package, "identity.csv"),
                index=False
            )
            commits_merged.to_csv(commits_path, index=False)
