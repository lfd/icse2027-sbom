import logging

from numpy import arange, where
from pandas import DataFrame, Series
from typing import Optional

logger = logging.getLogger(__name__)


def cross_release_key(data: DataFrame) -> Series:
    """
    Identify the same package across releases.

    Args:
        data: The rows of the model data set.

    Returns:
        One key per row.
    """
    upstream = data["upstream_url"].fillna("")
    downstream = data["downstream_url"].fillna("")
    if "downstream_path" in data.columns:
        # Packages in a mono repository share the URL, but not directories.
        downstream += "|" + data["downstream_path"].fillna("")

    # Use the upstream repository wherever there is one, and the downstream
    # repository otherwise, as the upstream repository is more stable and the
    # downstream repository is more likely to change between releases.
    return upstream.where(upstream != "", downstream)


def previous_severe(data: DataFrame, previous: DataFrame) -> Series:
    """
    Identify packages with severe vulnerabilities in the previous release.

    Args:
        data: The data frame of the release to rank.
        previous: The data frame of the previous release, with vulnerabilities.

    Returns:
        1 if the repository was affected in the previous release, 0 if it was
        not, and NaN if it was not part of the previous release.
    """
    affected = previous.groupby(cross_release_key(previous))["severe"].max()
    return cross_release_key(data).map(affected).astype(float)


def default_levels(
        data: DataFrame,
        previous: Optional[DataFrame] = None,
        size_feature: str = "loc",
        size_quantile: float = 0.75
) -> DataFrame:
    """
    Assign the attention level and the review order to the packages of one
    release by rules (high for repositories with severe vulnerabilities in the
    previous release, elevated for the largest packages, low for the rest).

    Args:
        data: The data of one release.
        previous: The data of the previous release, with the vulnerabilities.
        size_feature: The metric which rates the size of a package.
        size_quantile: The quantile of the size from which on a package
            is considered large.

    Returns:
        The previous state, the level, the review rank and the review priority
        in the graph of every row in the data.
    """
    result = DataFrame(index=data.index)
    if previous is not None:
        result["previous_severe"] = previous_severe(data, previous)
    else:
        logger.warning(
            "No previous release given, so no package is assigned the high "
            "attention level."
        )
        result["previous_severe"] = float("nan")

    size = data[size_feature]
    large = size >= size.quantile(size_quantile)
    level_index = Series(2, index=data.index)
    level_index = level_index.where(~large, 1)
    level_index = level_index.where(result["previous_severe"] != 1, 0)
    result["level"] = [["high", "elevated", "low"][i] for i in level_index]

    # Order packages by level and size.
    keys = DataFrame({"level": level_index, "size": -size}, index=data.index)
    order = keys.sort_values(["level", "size"], kind="mergesort")
    first_of_tie = ~order.eq(order.shift()).all(axis=1)
    positions = arange(1, len(order) + 1)
    ranks = Series(where(first_of_tie, positions, float("nan")),
                   index=order.index).ffill()
    result["rank"] = ranks.reindex(data.index).astype(int)
    result["priority"] = 1 - (result["rank"] - 1) / len(data)
    return result
