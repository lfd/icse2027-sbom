import json
import logging
import subprocess

from git import Repo
from git.exc import BadName, GitError
from pandas import read_csv, DataFrame
from dataclasses import dataclass
from os import path, makedirs

from sbom_analysis.analyse.package_metrics import PackageMetrics
from sbom_analysis.config.config import PackageInfo
from sbom_analysis.util import (analysis_windows, checkout_version,
                                repo_dir_name, safe_read_csv,
                                safe_read_commits, window_lag)

logger = logging.getLogger(__name__)


@dataclass
class MetricsSummary:
    """
    Bundles metrics across all packages and analyses.
    """

    package_metrics: dict[tuple[str, int], PackageMetrics] = None

    # Package meta information which is stored independent of the metrics
    # selected in the configuration.
    META_COLUMNS = [
        "package_name",
        "downstream_url",
        "downstream_checkout",
        "downstream_path",
        "downstream_primary_lang",
        "upstream_url",
        "upstream_checkout",
        "upstream_primary_lang",
        "window_start",
        "window_end"
    ]

    @staticmethod
    def primary_language(repo_dir: str) -> str:
        """
        Determine the primary programming language of a repository based on the
        most common code file types using CLOC.

        Args:
            repo_dir: Path to the local git repository.

        Returns:
            The name of the primary programming language or None.
        """
        logger.debug(
            "Determining primary programming language for project %s.",
            repo_dir
        )

        try:
            # Analys programming languages in the repository with CLOC.
            exclude = "YAML,JSON,CSV,Markdown,XML,HTML,Text,PO File,diff," \
                      "make,XSD"
            result = subprocess.run(
                [
                    "cloc",
                    repo_dir,
                    "--json",
                    "--quiet",
                    f"--exclude-lang={exclude}"
                ], capture_output=True, text=True, check=True
            )

            # Parse and process CLOC's JSON output.
            data = json.loads(result.stdout)
            data.pop('header', None)
            data.pop('SUM', None)
            if not data:
                return "unknown"

            # Find the most common programming language based on the number of
            # code files.
            primary_lang = max(
                data.items(), key=lambda x: x[1].get("code", 0)
            )[0]
            return primary_lang
        except Exception as e:
            logger.debug(e, exc_info=True)
            return "unknown"

    @classmethod
    def aggregate(
            cls,
            packages: dict[str, PackageInfo],
            repo_dir: str,
            extract_dir: str,
            analysis_dir: str,
            history_months: int,
            window_months: int,
            shift_months: int,
            selected_metrics: list[str]
    ) -> "MetricsSummary":
        """
        Calculate project-level metrics based on contribution and code analysis
        data.

        Args:
            packages: Dictionary of package identifiers and their metadata.
            repo_dir: Directory with the cloned git repositories.
            extract_dir: Directory where the extracted data is stored.
            analysis_dir: Directory where the analysis results will be stored.
            history_months: Maximum number of months to look back.
            window_months: Time interval in months for ratio calculations.
            shift_months: Number of months between the start of two
                consecutive windows.
            selected_metrics: List of metrics to calculate.
        """
        makedirs(analysis_dir, exist_ok=True)
        p_metrics_dict = dict()

        # Determine the time windows to aggregate metrics for. Windows may
        # overlap to obtain more data points.
        windows = analysis_windows(history_months, window_months, shift_months)

        # Trends always compare a full window length. With overlapping windows,
        # the preceding window is therefore more than one identifier away.
        lag = window_lag(window_months, shift_months)

        for package_id, package_info in packages.items():
            # Aggregate metrics from both upstream and downstream repositories.
            logger.info(
                f"Aggregating metrics for %s...",
                package_id
            )

            package_name = package_info.name
            down_url = package_info.downstream_repo
            down_checkout = package_info.downstream_checkout
            down_name = (repo_dir_name(down_url, "down")
                         if down_url else None)
            if down_name is not None:
                downstream_repo = path.join(repo_dir, down_name)
                downstream_lang = cls.primary_language(downstream_repo)
            else:
                downstream_lang = None

            up_url = package_info.upstream_repo
            up_checkout = package_info.upstream_checkout
            up_name = (repo_dir_name(up_url, "up")
                       if up_url else None)
            if up_name is not None:
                upstream_repo = path.join(repo_dir, up_name)
                upstream_lang = cls.primary_language(upstream_repo)
            else:
                upstream_lang = None

            # Read the commit history once.
            commit_path = path.join(
                extract_dir, package_name, f"commits.csv"
            )
            commit_table = safe_read_commits(commit_path)

            # Get reference time for activity metrics.
            reference_time = repo_name = checkout = None
            if down_name is not None:
                # Preferably, we check out the downstream version and use the
                # corresponding date as reference for temporal metrics.
                repo_name = down_name
                checkout = down_checkout
            elif up_name is not None:
                repo_name = up_name
                checkout = up_checkout

            if repo_name is not None and checkout is not None:
                # The repository may be missing or incomplete, e.g. if its
                # clone failed. In this case, the version cannot be checked
                # out.
                try:
                    repo = Repo(path.join(repo_dir, repo_name))
                    checkout_version(repo, checkout)
                    reference_time = repo.head.commit.committed_datetime
                except (GitError, BadName):
                    logger.warning(
                        "Could not check out version %s of repository %s.",
                        checkout,
                        repo_name,
                        exc_info=True
                    )

            if commit_table is None or reference_time is None:
                logger.warning(
                    "Could not aggregate commit metrics for package %s."
                    "Activity data is missing.",
                    package_id
                )

            # Iterate over time windows to aggregate metrics per window.
            for w, offset in windows.items():
                p_metrics = PackageMetrics(
                    package_name=package_name,
                    downstream_url=down_url,
                    downstream_checkout=down_checkout,
                    downstream_path=package_info.downstream_path,
                    downstream_primary_lang=downstream_lang,
                    upstream_url=up_url,
                    upstream_checkout=up_checkout,
                    upstream_primary_lang=upstream_lang
                )

                # Aggregate lizard code metrics.
                lizard_path = path.join(analysis_dir, "lizard", package_name)
                file_metrics_window = safe_read_csv(
                    path.join(lizard_path, f"file_metrics_{w}.csv")
                )
                file_metrics_prev_window = safe_read_csv(
                    path.join(lizard_path, f"file_metrics_{w-lag}.csv")
                )
                p_metrics.aggregate_lizard_metrics(
                    file_metrics_window,
                    file_metrics_prev_window,
                    selected_metrics
                )

                # Aggregate commit-level activity and contributor metrics.
                p_metrics.aggregate_commit_metrics(
                    commit_table,
                    file_metrics_window,
                    reference_time,
                    offset,
                    window_months,
                    selected_metrics
                )

                # Aggregate cppcheck static analysis results.
                cppcheck_path = path.join(
                    analysis_dir, "cppcheck", package_name
                )
                report_latest = safe_read_csv(
                    path.join(cppcheck_path, f"report_{w}.csv")
                )
                report_past = safe_read_csv(
                    path.join(cppcheck_path, f"report_{w-lag}.csv")
                )
                p_metrics.aggregate_cppcheck_metrics(
                    report_latest,
                    report_past,
                    file_metrics_window,
                    selected_metrics
                )

                # Aggregate OSV database statistics.
                osv_path = path.join(analysis_dir, "osv", package_info.name)
                osv_report = safe_read_csv(
                    path.join(osv_path, f"report_{package_info.version}.csv")
                )
                p_metrics.aggregate_osv_metrics(
                    osv_report,
                    file_metrics_window,
                    selected_metrics
                )

                p_metrics_dict[(package_id, w)] = p_metrics

        return cls(package_metrics=p_metrics_dict)

    @classmethod
    def from_csv(
            cls,
            file_path: str,
            selected_metrics: list[str]
    ) -> "MetricsSummary":
        """
        Load metrics from CSV.

        Args:
            file_path: Path to the input CSV file.
            selected_metrics: List of selected metrics stored in the DataFrame.

        Returns:
            An instance of Metrics with the selected metrics.
        """
        df = read_csv(file_path, header=0)
        p_metrics_dict = dict()

        # Load metrics of all packages.
        for idx, row in df.iterrows():
            p_metrics = PackageMetrics(
                package_name = row["package_name"],
                downstream_url = row["downstream_url"],
                downstream_checkout = row["downstream_checkout"],
                downstream_path = row.get("downstream_path"),
                downstream_primary_lang = row.get("downstream_primary_lang"),
                upstream_url = row["upstream_url"],
                upstream_checkout = row["upstream_checkout"],
                upstream_primary_lang = row.get("upstream_primary_lang")
            )

            # Depending on the user's configuration, some metrics may be
            # missing. Add only selected metrics to the object.
            for m in selected_metrics:
                if m in df.columns:
                    setattr(p_metrics, m, row[m])

            p_metrics_dict[(row["package_id"], row["window"])] = p_metrics

        return cls(package_metrics=p_metrics_dict)

    def to_csv(self, file_path: str, selected_metrics: list[str]) -> None:
        """
        Save metrics to CSV.

        Args:
            file_path: Path to the output CSV file.
            selected_metrics: List of metrics to store.
        """
        df = DataFrame.from_dict(
            {k: v.__dict__ for k, v in self.package_metrics.items()},
            orient="index"
        )

        # Store the package meta information and the configured metrics.
        columns = self.META_COLUMNS + [
            m for m in dict.fromkeys(selected_metrics)
            if m in df.columns and m not in self.META_COLUMNS
        ]
        df = df[columns]

        df.index.names = ["package_id", "window"]
        df.to_csv(file_path, index=True)
