import logging

from sbom_analysis.commands.input import ConfigInput
from sbom_analysis.config.config import Config
from sbom_analysis.extract.git_extractor import GitExtractor
from sbom_analysis.extract.identity import IdentityHandler

logger = logging.getLogger(__name__)


class ExtractCmd(ConfigInput):
    """
    Extract package-related information from Git.
    """

    @classmethod
    def run(cls, args):
        # Clone git repositories locally and determine the correct package
        # versions to use for the vulnerability analysis.
        conf = Config.from_yaml(args.conf_file)
        git_extractor = GitExtractor()
        conf.packages = git_extractor.clone(
            conf.packages,
            conf.repo_dir
        )

        # Extract the commit history for relevant versions with Perceval.
        git_extractor.extract(
            conf.packages,
            conf.repo_dir,
            conf.perceval_dir,
            conf.extract_dir,
            conf.history_months
        )
        conf.to_yaml(args.conf_file)

        # Merge diverging developer identities in the extracted data.
        identity_handler = IdentityHandler()
        identity_handler.merge(conf.extract_dir)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_config_input_args(parser)
