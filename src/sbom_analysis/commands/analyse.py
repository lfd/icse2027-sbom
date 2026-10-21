import logging

from os import path

from sbom_analysis.analyse.code_analyser import CodeAnalyser
from sbom_analysis.analyse.metrics_summary import MetricsSummary
from sbom_analysis.analyse.vulnerability_scan import VulnerabilityScanner
from sbom_analysis.commands.input import ConfigInput
from sbom_analysis.config.config import Config

logger = logging.getLogger(__name__)


class AnalyseCmd(ConfigInput):
    """
    Calculate metrics and annotate the dependency graph.
    """

    @classmethod
    def run(cls, args):
        conf = Config.from_yaml(args.conf_file)

        # Perform (static) code analysis if required by the metrics specified
        # in the configuration file.
        lizard_metrics = [
            "churn_per_function",
            "loc",
            "files",
            "functions",
            "function_growth",
            "cyclomatic_complexity",
            "cyclomatic_complexity_per_function",
            "cyclomatic_complexity_trend",
            "tokens",
            "tokens_per_function",
            "tokens_trend"
        ]
        lizard_analysis = any(t in conf.metrics for t in lizard_metrics)

        cppcheck_metrics = [
            "cppcheck_errors",
            "cppcheck_error_density",
            "cppcheck_error_trend",
            "cppcheck_warnings",
            "cppcheck_style_issues",
            "cppcheck_performance_issues",
            "cppcheck_portability_issues"
            "cppcheck_total_issues",
            "cppcheck_total_issue_density",
            "cppcheck_cwe_count",
            "cppcheck_cwe_density",
            "cppcheck_cwe_trend"
        ]
        cppcheck_analysis = any(t in conf.metrics for t in cppcheck_metrics)

        if cppcheck_analysis:
            # The cppcheck report only lists files with issues, so the lizard
            # file metrics are required to determine all files in a repository.
            lizard_analysis = True

        if lizard_analysis or cppcheck_analysis:
            code_analyser = CodeAnalyser()
            code_analyser.analyse(
                conf.packages,
                conf.repo_dir,
                conf.analysis_dir,
                conf.history_months,
                conf.window_months,
                conf.shift_months,
                conf.jobs,
                lizard_analysis,
                cppcheck_analysis
            )

        # Scan vulnerabilities in the package versions by querying the OSV
        # database.
        osv_metrics = [
            "critical_osv_count",
            "critical_osv_density",
            "high_osv_count",
            "medium_osv_count",
            "low_osv_count",
            "total_osv_count",
            "total_osv_density"
        ]
        osv_analysis = any(t in conf.metrics for t in osv_metrics)

        if osv_analysis:
            v_scanner = VulnerabilityScanner()
            v_scanner.scan(conf.packages, conf.analysis_dir)

        # Aggregate metrics at package level.
        metrics_path = path.join(conf.analysis_dir, "metrics.csv")
        metrics = MetricsSummary.aggregate(
            conf.packages,
            conf.repo_dir,
            conf.extract_dir,
            conf.analysis_dir,
            conf.history_months,
            conf.window_months,
            conf.shift_months,
            conf.metrics
        )
        metrics.to_csv(metrics_path, conf.metrics)

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_config_input_args(parser)
