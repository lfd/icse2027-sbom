import logging
import yaml

from dataclasses import dataclass, field
from os import path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """
    Configuration to fit an attention score model.

    Contains data set processing and model parameter details.
    """

    # Name of the model, used for output files.
    name: str = "attention-score"

    # Configurations of the releases to fit on.
    conf_files: List[str] = field(default_factory=list)
    releases: List[str] = field(default_factory=list)

    # Features to fit the attention score on.
    features: List[str] = field(default_factory=list)
    # The OSV severities which should be considered as relevant vulnerability.
    severities: List[str] = field(default_factory=lambda: ["critical", "high"])
    # Date (YYYY-MM-DD) until which vulnerabilities are counted to avoid data
    # leakage.
    published_before: Optional[str] = None

    # Inverse regularisation strength (smaller values penalise/regularise more).
    penalty: float = 1.0
    # Bootstrap samples over repositories for the coefficient intervals, 0 to
    # exclude the intervals and just fit once.
    bootstrap: int = 500
    # The two quantiles to separate the "low", "elevated" and "high" attention
    # levels.
    level_quantiles: List[float] = field(default_factory=lambda: [0.25, 0.75])

    # Score every package with a model fitted without its repository
    # (leave-one-repository-out).
    cross_validate: bool = True
    # Seed of the resampling.
    seed: int = 12345

    # Directory to store the fitted model in.
    model_dir: str = "data/model"
    # File to store the fitted model.
    model_file: Optional[str] = None

    def __post_init__(self):
        if self.published_before is not None:
            self.published_before = str(self.published_before)
        if self.model_file is None:
            self.model_file = path.join(self.model_dir, f"{self.name}.json")

    @classmethod
    def from_yaml(cls, conf_file: str) -> "ModelConfig":
        """
        Load a model configuration from an existing YAML file.
        """
        with open(conf_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or dict()
        return cls(**data)
