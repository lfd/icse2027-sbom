import json
import logging

from hashlib import sha256

from dataclasses import asdict
from os import makedirs, path

from sbom_analysis.commands.input import ModelInput
from sbom_analysis.config.config import Config
from sbom_analysis.config.model_config import ModelConfig
from sbom_analysis.model.dataset import build_dataset
from sbom_analysis.model.logistic import (build_model,
                                          coefficient_table,
                                          out_of_fold_scores)
from sbom_analysis.model.score import level_of, score_data

logger = logging.getLogger(__name__)


class FitCmd(ModelInput):
    """
    Fit the package attention score on the calculated metrics.
    """

    @classmethod
    def run(cls, args):
        model_conf = ModelConfig.from_yaml(args.model_conf_file)
        configs = [Config.from_yaml(f) for f in model_conf.conf_files]
        releases = cls.release_names(configs, model_conf.releases)
        logger.info(
            "Fitting %s on %s...", model_conf.name, ", ".join(releases)
        )

        metrics_files = [
            path.join(c.analysis_dir, "metrics.csv") for c in configs
        ]
        data = build_dataset(
            metrics_files,
            releases,
            model_conf.features,
            severities=model_conf.severities,
            published_before=model_conf.published_before,
            configs=configs
        )
        model = build_model(
            data,
            model_conf.features,
            releases,
            model_conf.severities,
            penalty=model_conf.penalty,
            bootstrap=model_conf.bootstrap,
            level_quantiles=model_conf.level_quantiles,
            seed=model_conf.seed
        )

        # Store the model configuration for reproducibility.
        model["provenance"]["model_conf"] = {
            k: v for k, v in asdict(model_conf).items() if k != "model_file"
        }
        # Store the digests to check whether a model was fitted on the same
        # data later on.
        model["provenance"]["metrics_digests"] = {
            file: cls.digest(file) for file in metrics_files
        }

        out_dir = path.dirname(model_conf.model_file)
        if out_dir and not path.exists(out_dir):
            makedirs(out_dir)

        with open(model_conf.model_file, "w", encoding="utf-8") as f:
            json.dump(model, f, indent=2)
        logger.info("Model stored in %s", model_conf.model_file)

        # Construct coefficient table.
        base = path.splitext(model_conf.model_file)[0]
        table = coefficient_table(model)
        table.to_csv(f"{base}_coefficients.csv", index=False)

        # Score and store data (cross-validated).
        data["attention_score"], data["attention_level"] = score_data(
            model, data
        )
        if model_conf.cross_validate:
            # Score every package with a model trained without its own
            # repository/repository-directory combination.
            data["cv_score"] = out_of_fold_scores(
                data, model_conf.features, model_conf.penalty
            )
            data["cv_level"] = [
                level_of(s, model["levels"]["names"],
                         model["levels"]["thresholds"])
                for s in data["cv_score"]
            ]
        data.to_csv(f"{base}_data.csv", index=False)

    @staticmethod
    def digest(file_path: str) -> str:
        """
        Get the digest of a file to identify the data set a model was trained
        on.

        Args:
            file_path: Path to the file.

        Returns:
            The first sixteen characters of the digest.
        """
        with open(file_path, "rb") as f:
            return sha256(f.read()).hexdigest()[:16]

    @classmethod
    def release_names(cls, configs: list, names: list) -> list:
        """
        Ensure that releases can be distinguished by name.

        Args:
            configs: The configurations of the releases.
            names: The names of the configurations, empty list to derive them.

        Returns:
            One unique name per configuration.
        """
        releases = names or [c.name for c in configs]

        if len(set(releases)) != len(releases):
            releases = [path.basename(c.analysis_dir) for c in configs]

        if len(set(releases)) != len(releases):
            raise ValueError(
                f"Releases {', '.join(releases)} are not distinct. Please "
                f"check the configuration."
            )

        return releases

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_model_input_args(parser)
