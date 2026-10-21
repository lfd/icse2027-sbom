import logging

logger = logging.getLogger(__name__)


class SbomInput:
    """
    Provides options for SBOM input.
    """

    @classmethod
    def parser_add_sbom_input_args(cls, parser):
        parser.add_argument(
            "sbom_file",
            type=str,
            help="SBOM file to process"
        )
        parser.add_argument(
            "conf_file",
            type=str,
            help="Configuration file path"
        )


class ConfigInput:
    """
    Provides options for configuration file input.
    """

    @classmethod
    def parser_add_config_input_args(cls, parser):
        parser.add_argument(
            "conf_file",
            type=str,
            help="Configuration file to process"
        )


class ModelInput:
    """
    Provides options for model configuration file input.
    """

    @classmethod
    def parser_add_model_input_args(cls, parser):
        parser.add_argument(
            "model_conf_file",
            type=str,
            help="Model configuration file to process"
        )


class ModelFileInput:
    """
    Provides options for fitted model file input.
    """

    @classmethod
    def parser_add_model_file_args(cls, parser):
        parser.add_argument(
            "--model_file",
            type=str,
            default=None,
            help="Fitted model file to process"
        )


class PreviousReleaseInput:
    """
    Provides options for the configuration file input of the previous release.
    """

    @classmethod
    def parser_add_previous_release_args(cls, parser):
        parser.add_argument(
            "--previous_conf_file",
            type=str,
            default=None,
            help="Configuration file of the previous release"
        )
        parser.add_argument(
            "--published_before",
            type=str,
            default=None,
            help="Date (YYYY-MM-DD) until which vulnerabilities are "
                 "considered in the previous release"
        )


class GraphInput:
    """
    Provides options for graph file input.
    """

    @classmethod
    def parser_add_graph_input_args(cls, parser):
        parser.add_argument(
            "conf_file",
            type=str,
            help="Configuration file to process"
        )
        parser.add_argument(
            "graph_file",
            type=str,
            help="SBOM graphml file to process"
        )
