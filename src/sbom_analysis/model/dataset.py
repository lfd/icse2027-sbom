import logging

from datetime import date
from os import path
from pandas import DataFrame, concat, read_csv
from typing import List, Optional

from sbom_analysis.config.config import Config

logger = logging.getLogger(__name__)


def vulnerabilities_published_before(
        conf: Config,
        severities: List[str],
        published_before: str
) -> dict[str, int]:
    """
    Count the vulnerabilities of every package of a release which were
    published before a date, to consider only what was known at that time.

    Args:
        conf: The configuration of the release.
        severities: The severities which count as a vulnerability.
        published_before: The date (YYYY-MM-DD) before which a vulnerability
            must have been published.

    Returns:
        The number of vulnerabilities per package identifier, for the packages
        which were scanned.
    """
    counts = {}
    undated = 0
    for package_id, package_info in conf.packages.items():
        report_file = path.join(conf.analysis_dir, "osv", package_info.name,
                                f"report_{package_info.version}.csv")
        if not path.exists(report_file):
            continue

        report = read_csv(report_file, dtype=str).fillna("")
        if "published" not in report.columns:
            raise ValueError(
                f"The OSV report {report_file} has no publication dates. "
                f"Please rerun the analyse command."
            )

        severe = report[report["severity_class"].str.lower().isin(severities)]
        published = severe["published"].str[:10]
        undated += int((published == "").sum())
        counts[package_id] = int(
            ((published != "") & (published < published_before)).sum()
        )

    if undated:
        logger.warning(
            "%d vulnerabilities of %s have no publication date and are not "
            "counted.", undated, conf.name
        )
    return counts


def read_release_metrics(metrics_file: str, release: str) -> DataFrame:
    """
    Read the metrics of one release.

    Args:
        metrics_file: Path to the metrics of the release.
        release: Name of the release.

    Returns:
        The observed package windows.
    """
    data = read_csv(metrics_file)

    # Drop windows that would end before the first commit.
    observed = data[data["project_age"].notna()].copy()
    observed["release"] = release
    return observed


def build_dataset(
        metrics_files: List[str],
        releases: List[str],
        features: List[str],
        severities: Optional[List[str]] = None,
        keep_shared: bool = False,
        published_before: Optional[str] = None,
        configs: Optional[List[Config]] = None
) -> DataFrame:
    """
    Build the data frame the model is fitted on, with one row per repository
    combination, or repository-directory combination in case of mono
    repositories.

    As the vulnerability counts can only be determined per package version,
    not repository states, the features are averaged over the windows of the
    history to describe the development which produced the shipped version in
    a single row. The history is anchored at the version, so every window
    precedes it.

    Args:
        metrics_files: The metrics files, one per release.
        releases: The release names, in the order of the files.
        features: The metric columns to use as features.
        severities: The severities which count as a vulnerability for the
            target, ["critical", "high"] by default.
        keep_shared: Keep every package which shares a combination instead
            of one row per combination (useful for annotation).
        published_before: Date (YYYY-MM-DD) until which vulnerabilities
            are counted.
        configs: The configurations of the releases, in the order of the
            files. Required with published_before to find the OSV reports.

    Returns:
        One row per combination and release, with the features, the target
        and the columns which identify the row.
    """
    severities = severities or ["critical", "high"]
    targets = [f"{s}_osv_count" for s in severities]

    # Combine metrics of all releases.
    data = concat(
        [read_release_metrics(f, r) for f, r in zip(metrics_files, releases)],
        ignore_index=True
    )

    # Get the combinations of repositories (and directories for mono
    # repositories) for analysis.
    path = (data["downstream_path"].fillna("")
            if "downstream_path" in data.columns else "")
    data["combination"] = (data["downstream_url"].fillna("") + "|"
                    + data["upstream_url"].fillna("") + "|" + path)

    # Summarise vulnerability counts from the requested severity columns of the
    # shipped package versions.
    data["vulnerabilities"] = data[targets].sum(axis=1)

    if published_before is not None:
        published_before = date.fromisoformat(
            str(published_before)
        ).isoformat()

        logger.info(
            "Counting only vulnerabilities published before %s.",
            published_before
        )

        for conf, release in zip(configs, releases):
            counts = vulnerabilities_published_before(
                conf, severities, published_before
            )
            rows = data["release"] == release
            # Ignore vulnerabilities which were published after the requested
            # date.
            data.loc[rows, "vulnerabilities"] = (
                data.loc[rows, "package_id"].map(counts).fillna(0)
            )

    # Aggregate data to one row per combination of repositories, directories
    # and release. The features are the mean over all windows of the history,
    # the target is the vulnerability state of the shipped version.
    aggregated = data.groupby(["release", "combination"], as_index=False).agg(
        **{f: (f, "mean") for f in features},
        vulnerabilities=("vulnerabilities", "max"),
        package_name=("package_name", "first"),
        package_id=("package_id", "first"),
        packages=("package_name", "nunique"),
        downstream_url=("downstream_url", "first"),
        upstream_url=("upstream_url", "first"),
        **({"downstream_path": ("downstream_path", "first")}
           if "downstream_path" in data.columns else {})
    )

    if keep_shared:
        # Every package which shares a combination keeps its own row, although
        # leading to duplicate metrics.
        # This path is only relevant for annotation, not for model fitting.
        names = data[
            ["release", "combination", "package_name", "package_id"]
        ].drop_duplicates()
        aggregated = names.merge(
            aggregated.drop(columns=["package_name", "package_id"]),
            on=["release", "combination"], how="left"
        )

    # Set the target to 1 if there is at least one vulnerability of the
    # requested severities.
    aggregated["severe"] = (aggregated["vulnerabilities"] > 0).astype(int)

    # Remove rows with missing features, as they could neither be fitted nor
    # scored.
    complete = aggregated.dropna(subset=features)
    logger.info(
        "Model data set: %d rows of %d combinations, %d with a vulnerability "
        "of severity %s, %d rows dropped for a missing feature",
        len(complete), complete["combination"].nunique(),
        int(complete["severe"].sum()), "/".join(severities),
        len(aggregated) - len(complete)
    )
    return complete
