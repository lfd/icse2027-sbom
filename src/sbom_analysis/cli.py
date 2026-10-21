import argparse
import logging
import sys

from time import perf_counter

from sbom_analysis.commands.setup_config import SetupConfigCmd
from sbom_analysis.commands.extract import ExtractCmd
from sbom_analysis.commands.analyse import AnalyseCmd
from sbom_analysis.commands.annotate import AnnotateCmd
from sbom_analysis.commands.fit import FitCmd

logger = logging.getLogger(__name__)


def setup_parser():
    """
    Set up the command line argument parser with subcommands for each analysis
    step.
    """
    parser = argparse.ArgumentParser(
        prog="sbom-analysis",
        description="Analyses for SBOM packages",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="increase verbosity"
    )

    subparsers = parser.add_subparsers(
        help="sub command help",
        dest="cmd",
        required=True
    )
    SetupConfigCmd.setup_parser(
        subparsers.add_parser(
            "setup-config",
            help="create the initial analysis configuration from an SBOM"
        )
    )
    ExtractCmd.setup_parser(
        subparsers.add_parser(
            "extract",
            help="extract history from the package git repositories"
        )
    )
    AnalyseCmd.setup_parser(
        subparsers.add_parser(
            "analyse",
            help="analyse the extracted data and calculate metrics"
        )
    )
    FitCmd.setup_parser(
        subparsers.add_parser(
            "fit",
            help="fit a package attention score on the calculated metrics"
        )
    )
    AnnotateCmd.setup_parser(
        subparsers.add_parser(
            "annotate",
            help="annotate an existing dependency graph"
        )
    )

    return parser


def main():
    start = perf_counter()
    parser = setup_parser()
    args = parser.parse_args()

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose == 2:
        level = logging.DEBUG

    logging.basicConfig(level=level)

    try:
        if args.cmd == "setup-config":
            SetupConfigCmd.run(args)
        elif args.cmd == "extract":
            ExtractCmd.run(args)
        elif args.cmd == "analyse":
            AnalyseCmd.run(args)
        elif args.cmd == "fit":
            FitCmd.run(args)
        elif args.cmd == "annotate":
            AnnotateCmd.run(args)
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit(-1)
    finally:
        total_seconds = int(perf_counter() - start)
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        logger.info("Time: %02d:%02d:%02d (hh:mm:ss)",
                    hours, minutes, seconds)


if __name__ == "__main__":
    main()