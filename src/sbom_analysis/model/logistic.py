import logging

from datetime import date
from numpy import asarray, exp, percentile, quantile, unique
from numpy.random import default_rng
from pandas import DataFrame, Series, concat
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def fit(rows: DataFrame, features: List[str], penalty: float):
    """
    Fit a logistic regression on the scaled data set.

    Args:
        rows: The rows to fit on.
        features: The feature columns.
        penalty: The inverse regularisation strength.

    Returns:
        The regression coefficients, the intercept, the means and the
        deviations the features were scaled by.
    """
    # Standard-scale features for comparability.
    scaler = StandardScaler()
    X = scaler.fit_transform(rows[features].to_numpy(dtype=float))

    # Fit the regression model.
    model = LogisticRegression(C=penalty, max_iter=5000)
    model.fit(X, rows["severe"].to_numpy())

    return (model.coef_[0], float(model.intercept_[0]),
            scaler.mean_, scaler.scale_)


def bootstrap_coefficients(
        data: DataFrame,
        features: List[str],
        penalty: float,
        runs: int = 500,
        seed: int = 42
) -> Dict[str, Dict[str, float]]:
    """
    Resamples the combinations of repositories (and repository-directories)
    to evaluate stability of each coefficient.

    Args:
        data: The model data set.
        features: The feature columns.
        penalty: The inverse regularisation strength.
        runs: Number of bootstrap samples.
        seed: Seed of the resampling, so that a run can be repeated.

    Returns:
        The 2.5th and 97.5th percentile of each feature's coefficient and
        the share of samples in which it kept the sign of the majority.
    """
    rng = default_rng(seed)
    combinations = unique(data["combination"].to_numpy())
    groups = {c: rows for c, rows in data.groupby("combination")}
    drawn = {f: [] for f in features}

    # Randomly draw as many combinations as there are, with replacement, and
    # fit models on them. The same combination can be drawn multiple times
    # and then contributes its rows as often as it was drawn. Deduplicating
    # the sample would subsample rather than bootstrap and result in too narrow
    # intervals.
    for run in range(runs):
        sample = rng.choice(combinations, size=len(combinations), replace=True)
        rows = concat([groups[c] for c in sample], ignore_index=True)
        if rows["severe"].nunique() < 2:
            # Skip samples with only one class.
            continue
        try:
            coefficients, _, _, _ = fit(rows, features, penalty)
        except Exception as e:
            logger.debug("Bootstrap run %d did not converge: %s", run, e)
            continue
        for feature, value in zip(features, coefficients):
            drawn[feature].append(value)

    # Aggregate summary statistics for each feature.
    summary = dict()
    for feature, values in drawn.items():
        if not values:
            summary[feature] = {"low": float("nan"), "high": float("nan"),
                                "same_sign": float("nan")}
            continue
        values = asarray(values)
        positive = float((values > 0).mean())
        summary[feature] = {
            "low": float(percentile(values, 2.5)),
            "high": float(percentile(values, 97.5)),
            # How often the coefficient pointed the same way as the majority,
            # which could indicate stability of the relationship.
            "same_sign": float(max(positive, 1 - positive))
        }
    return summary


def per_release_coefficients(
        data: DataFrame,
        features: List[str],
        penalty: float
) -> Dict[str, Dict[str, float]]:
    """
    Fit a logistic regression model on every release on its own.

    Args:
        data: The model data set.
        features: The feature columns.
        penalty: The inverse regularisation strength.

    Returns:
        The coefficient of every feature, per release.
    """
    coefficients = dict()
    for release in data["release"].unique():
        rows = data[data["release"] == release]
        if rows["severe"].nunique() < 2:
            # Skip releases with only one class.
            continue
        try:
            values, _, _, _ = fit(rows, features, penalty)
        except Exception as e:
            logger.warning(
                "Could not fit release-specific model for %s: %s",
                release,
                e
            )
            continue
        coefficients[str(release)] = dict(zip(features, map(float, values)))
    return coefficients


def univariate_coefficients(
        data: DataFrame,
        features: List[str],
        penalty: float,
        bootstrap: int = 500,
        seed: int = 42
) -> Dict[str, Dict]:
    """
    Fits a logistic regression for every feature on its own.

    This reveals discrepancies of a feature's coefficient in the multivariate
    model and on its own, meaning that a feature is used in the multivariate
    model to correct another feature rather than reporting an association of
    its own.

    Args:
        data: The data set used for the multivariate model.
        features: The feature columns.
        penalty: The inverse regularisation strength.
        bootstrap: Bootstrap samples over combinations, 0 to leave out.
        seed: Seed of the resampling.

    Returns:
        Per feature, its coefficient on its own, the interval around it and
        the same fit per release.
    """
    univariate = dict()

    for feature in features:
        # Fit a univariate model for the specific feature.
        coefficients, _, _, _ = fit(data, [feature], penalty)
        entry = {"coefficient": float(coefficients[0])}

        if bootstrap > 0:
            # Bootstrap the univariate model to get confidence intervals and
            # stability indicators.
            entry.update(bootstrap_coefficients(
                data, [feature], penalty, runs=bootstrap, seed=seed
            )[feature])

        # Fit the univariate model on every release on its own, to see whether
        # the releases agree on the direction of the association.
        entry["per_release"] = {
            release: values[feature] for release, values
            in per_release_coefficients(data, [feature], penalty).items()
        }
        univariate[feature] = entry

    return univariate


def out_of_fold_scores(
        data: DataFrame,
        features: List[str],
        penalty: float
) -> Series:
    """
    Scores every row of the data set with a model which does not know its
    repository/directory combination (leave-one-out).

    Args:
        data: The model data set.
        features: The feature columns.
        penalty: The inverse regularisation strength.

    Returns:
        One score per row, from a model fitted without its combination.
    """
    scores = Series(float("nan"), index=data.index)

    for combination in data["combination"].unique():
        held_out = data["combination"] == combination
        rest = data[~held_out]
        if rest["severe"].nunique() < 2:
            # Skip remaining combinations if they only have one class.
            continue

        # Fit the model on the rest and score the held-out rows.
        coefficients, intercept, means, deviations = fit(rest, features,
                                                         penalty)
        X = data.loc[held_out, features].to_numpy(dtype=float)
        scaled = (X - means) / deviations
        scores[held_out] = 1.0 / (1.0 + exp(-(scaled @ coefficients
                                              + intercept)))

    return scores


def build_model(
        data: DataFrame,
        features: List[str],
        releases: List[str],
        severities: List[str],
        penalty: float = 1.0,
        bootstrap: int = 500,
        level_quantiles: Optional[List[float]] = None,
        seed: int = 42
) -> Dict:
    """
    Fit the attention score model and analyse its coefficients.

    Args:
        data: The model data set.
        features: The feature columns.
        releases: The releases the data set was built from.
        severities: The severities which count as a vulnerability.
        penalty: The inverse regularisation strength.
        bootstrap: Number of bootstrap samples, 0 to leave them out.
        level_quantiles: The two quantiles which separate the three score levels.
        seed: Seed of the resampling.

    Returns:
        The model as a dictionary.
    """
    score_levels = ["low", "elevated", "high"]
    if data["severe"].nunique() < 2:
        raise ValueError(
            "The data set has only one class. Model cannot be fitted."
        )

    # Fit the score model on the pooled data and derive the thresholds for the
    # attention score levels.
    coefficients, intercept, means, deviations = fit(data, features, penalty)
    scaled = (data[features].to_numpy(dtype=float) - means) / deviations
    scores = 1.0 / (1.0 + exp(-(scaled @ coefficients + intercept)))
    thresholds = [float(quantile(scores, q))
                  for q in level_quantiles or [0.25, 0.75]]
    logger.debug(
        "Fitted attention score model on %d rows, %d of them with vulnerability.",
        len(data),
        int(data["severe"].sum())
    )

    # Analyse the coefficients and return the model as well as the
    # coefficient analysis results as a dictionary.
    return {
        "target": "_".join(severities) + "_osv",
        "severities": severities,
        "features": features,
        "scaler": {
            "mean": [float(m) for m in means],
            "sd": [float(s) for s in deviations]
        },
        "coefficients": [float(c) for c in coefficients],
        "intercept": intercept,
        "levels": {"names": score_levels, "thresholds": thresholds},
        "provenance": {
            "releases": releases,
            "rows": int(len(data)),
            "combinations": int(data["combination"].nunique()),
            "affected": int(data["severe"].sum()),
            "penalty": penalty,
            "fitted": date.today().isoformat()
        },
        "stability": bootstrap_coefficients(
            data, features, penalty, runs=bootstrap, seed=seed
        ) if bootstrap > 0 else {},
        "per_release": per_release_coefficients(data, features, penalty),
        "univariate": univariate_coefficients(
            data, features, penalty, bootstrap=bootstrap, seed=seed
        )
    }


def coefficient_table(model: Dict) -> DataFrame:
    """
    Create the coefficient table.

    Args:
        model: The model as build_model() returned it.

    Returns:
        One row per feature, with its coefficient beside the others and on
        its own, the bootstrap intervals, and one column per release.
    """
    stability = model.get("stability", {})
    per_release = model.get("per_release", {})
    univariate = model.get("univariate", {})
    nan = float("nan")

    rows = []
    for feature, coefficient in zip(model["features"], model["coefficients"]):
        drawn = stability.get(feature, {})
        uni = univariate.get(feature, {})
        row = {
            "feature": feature,
            "coefficient": coefficient,
            "ci_low": drawn.get("low", nan),
            "ci_high": drawn.get("high", nan),
            "same_sign": drawn.get("same_sign", nan),
            "uni": uni.get("coefficient", nan),
            "uni_ci_low": uni.get("low", nan),
            "uni_ci_high": uni.get("high", nan)
        }
        for release, values in per_release.items():
            row[f"release_{release}"] = values.get(feature, nan)
        for release, value in uni.get("per_release", {}).items():
            row[f"uni_release_{release}"] = value

        # Whether the univariate coefficient agrees with the multivariate
        # coefficient.
        row["agrees_uni"] = (
            uni["coefficient"] * coefficient > 0 if uni else nan
        )
        # Whether every release points the same way as the pooled model.
        signs = [v[feature] for v in per_release.values() if feature in v]
        row["releases_agree"] = (
            all(s * coefficient > 0 for s in signs) if signs else nan
        )
        rows.append(row)
    return DataFrame(rows)
