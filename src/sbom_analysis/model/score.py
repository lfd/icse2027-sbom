import json
import logging

from numpy import asarray, exp
from pandas import DataFrame
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


def read_model(model_file: str) -> Dict:
    """
    Read a fitted attention score model.

    Args:
        model_file: Path to the model.

    Returns:
        The model as a dictionary.
    """
    with open(model_file, "r", encoding="utf-8") as f:
        model = json.load(f)

    required = ["features", "scaler", "coefficients", "intercept", "levels"]
    missing = [k for k in required if k not in model]
    if missing:
        raise ValueError(
            f"{model_file} is not a complete fitted model, it lacks "
            f"{', '.join(missing)}."
        )
    if len(model["features"]) != len(model["coefficients"]):
        raise ValueError(
            f"{model_file} has {len(model['features'])} features but "
            f"{len(model['coefficients'])} coefficients."
        )
    return model


def score_data(model: Dict, data: DataFrame) -> Tuple[List[float], List[str]]:
    """
    Score packages with a fitted model.

    Args:
        model: The loaded model.
        data: One feature row per package.

    Returns:
        The attention scores and score levels.
    """
    features = model["features"]
    missing = [f for f in features if f not in data.columns]
    if missing:
        raise ValueError(
            f"Cannot score data without {', '.join(missing)}, which the "
            f"model requires."
        )

    # Extract features.
    X = data[features].to_numpy(dtype=float)

    # Scale the features with the fitted scaler.
    means = asarray(model["scaler"]["mean"], dtype=float)
    deviations = asarray(model["scaler"]["sd"], dtype=float)
    coefficients = asarray(model["coefficients"], dtype=float)
    scaled = (X - means) / deviations

    # Compute the attention scores with the fitted coefficients and intercept.
    scores = 1.0 / (1.0 + exp(-(scaled @ coefficients + model["intercept"])))

    # Assign the attention score levels based on the fitted thresholds.
    names = model["levels"]["names"]
    thresholds = model["levels"]["thresholds"]
    levels = [level_of(s, names, thresholds) for s in scores]
    return [float(s) for s in scores], levels


def level_of(value: float, names: List[str], thresholds: List[float]) -> str:
    """
    Assign the attention score level (low, elevated, high) based on the score.

    Args:
        value: The attention score.
        names: The levels, from lowest to highest.
        thresholds: The boundaries between them, one fewer than the names.

    Returns:
        The name of the level.
    """
    for name, threshold in zip(names, thresholds):
        if value < threshold:
            return name
    return names[-1]
