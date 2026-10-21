import logging

from os import path

from sbom_analysis.config.config import Config
from sbom_analysis.commands.input import SbomInput

logger = logging.getLogger(__name__)


class SetupConfigCmd(SbomInput):
    """
    Processes an SBOM and creates a minimal configuration file for analysis.
    """

    @classmethod
    def run(cls, args):
        conf = Config()
        # Derive a unique directory name from the SBOM file name.
        dir_name = path.splitext(path.basename(args.conf_file))[0]
        conf.generate(args.sbom_file, dir_name)
        conf.to_yaml(args.conf_file)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_sbom_input_args(parser)