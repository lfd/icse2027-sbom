import logging

from os import path
from pandas import DataFrame

from sbom_analysis.analyse.metrics_summary import MetricsSummary
from sbom_analysis.annotate.graph import Graph
from sbom_analysis.commands.input import (GraphInput, ModelFileInput,
                                          PreviousReleaseInput)
from sbom_analysis.config.config import Config
from sbom_analysis.model.dataset import build_dataset
from sbom_analysis.model.rule import default_levels
from sbom_analysis.model.score import read_model, score_data

logger = logging.getLogger(__name__)


class AnnotateCmd(GraphInput, ModelFileInput, PreviousReleaseInput):
    """
    Annotate the dependency graph with the calculated metrics and the
    attention level, assigned by either a fitted model, the vulnerability
    history and/or the size of the packages.
    """

    @classmethod
    def run(cls, args):
        conf = Config.from_yaml(args.conf_file)

        # Load metrics.
        metrics_path = path.join(conf.analysis_dir, "metrics.csv")
        metrics = MetricsSummary.from_csv(metrics_path, conf.metrics)

        # Annotate the dependency graph with the calculated metrics.
        graph = Graph.from_graphml(args.graph_file)
        graph.annotate(metrics, conf.metrics)

        # The output files are named based on the model or rule.
        base = path.join(conf.analysis_dir, "graph_annotated")
        if args.model_file:
            if args.previous_conf_file or args.published_before:
                logger.info("Model and previous release info were provided. "
                            "Using the model only.")
            table = cls.annotate_scores(graph, conf, metrics_path,
                                        args.model_file)
            base += "_" + path.splitext(path.basename(args.model_file))[0]
        else:
            table = cls.annotate_default(graph, conf, metrics_path,
                                         args.previous_conf_file,
                                         args.published_before)
            base += "_rule"

        graph.to_graphml(base + ".graphml")
        graph.to_html(base + ".html")
        table.to_csv(base + ".csv", index=False)

    @classmethod
    def annotate_scores(
            cls,
            graph: Graph,
            conf: Config,
            metrics_path: str,
            model_file: str
    ) -> DataFrame:
        """
        Score the packages of the release with a fitted model and store the
        result in the graph.

        Args:
            graph: The dependency graph to annotate.
            conf: The configuration of the release.
            metrics_path: Path to the metrics of the release.
            model_file: Path to the fitted model.

        Returns:
            The scored packages of the graph.
        """
        model = read_model(model_file)
        logger.info(
            "Scoring packages with the model fitted on %s...",
            ", ".join(model.get("provenance", {}).get("releases", ["?"]))
        )

        # Rebuild the model features for all repositories, including the ones
        # from mono repositories.
        values = build_dataset(
            [metrics_path],
            [conf.name],
            model["features"],
            severities=model.get("severities"),
            # Every package needs a score, so the packages which share a
            # combination are not collapsed as they are for the fit.
            keep_shared=True
        )
        scores, levels = score_data(model, values)
        values["attention_score"] = scores
        values["attention_level"] = levels

        # Determine the review order the score implies.
        values["rank"] = values["attention_score"].rank(
            ascending=False, method="min"
        ).astype(int)
        return cls.store_levels(graph, values)

    @classmethod
    def annotate_default(
            cls,
            graph: Graph,
            conf: Config,
            metrics_path: str,
            previous_conf_file: str = None,
            published_before: str = None
    ) -> DataFrame:
        """
        Assign the attention levels without a model, by the vulnerabilities
        of the previous release and/or the size of the packages.

        Args:
            graph: The dependency graph to annotate.
            conf: The configuration of the release.
            metrics_path: Path to the metrics of the release.
            previous_conf_file: Path to the configuration of the previous
                release.
            published_before: Date (YYYY-MM-DD) until which vulnerabilities
                are counted.

        Returns:
            The ranked packages of the graph.
        """
        logger.info("Assigning attention levels by history and size...")

        # Get the size.
        size_feature = "loc"
        values = build_dataset(
            [metrics_path],
            [conf.name],
            [size_feature],
            keep_shared=True
        )

        previous = None
        if previous_conf_file:
            # Get vulnerabilities from previous release, optionally only those
            # published before a date to avoid leaking vulnerability data not
            # available at the time.
            previous_conf = Config.from_yaml(previous_conf_file)
            previous = build_dataset(
                [path.join(previous_conf.analysis_dir, "metrics.csv")],
                [previous_conf.name],
                [],
                published_before=published_before,
                configs=[previous_conf]
            )
        elif published_before:
            logger.info(
                "A publication date but no previous release were given. "
                "Ignoring the date."
            )

        # Rank the packages.
        result = default_levels(values, previous, size_feature=size_feature)
        values["previous_severe"] = result["previous_severe"]
        values["attention_score"] = result["priority"]
        values["attention_level"] = result["level"]
        values["rank"] = result["rank"]

        return cls.store_levels(graph, values)

    @staticmethod
    def store_levels(graph: Graph, values: DataFrame) -> DataFrame:
        """
        Store the attention score and level of every package.

        Args:
            graph: The dependency graph to annotate.
            values: The scored rows.

        Returns:
            The rows of the packages in the graph, with their repositories,
            vulnerabilities, attention score, level and rank.
        """
        ids = values["package_id"].str.removeprefix("SPDXRef-")
        in_graph = ids.isin(set(graph.G.nodes()))
        if not in_graph.any():
            logger.warning(
                "None of the %d scored packages is a node of the graph."
                "Skipping attention score.",
                len(values)
            )

        matched = values[in_graph]
        graph.annotate_scores(
            dict(zip(ids[in_graph], matched["attention_score"])),
            dict(zip(ids[in_graph], matched["attention_level"])),
            dict(zip(ids[in_graph], matched["severe"]))
        )

        columns = ["package_id", "package_name", "downstream_url",
                   "upstream_url", "downstream_path", "vulnerabilities",
                   "severe", "previous_severe", "attention_score",
                   "attention_level", "rank"]
        return matched[[c for c in columns if c in matched.columns]]

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_graph_input_args(parser)
        cls.parser_add_model_file_args(parser)
        cls.parser_add_previous_release_args(parser)
