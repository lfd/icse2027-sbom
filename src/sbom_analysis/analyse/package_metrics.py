import logging

from dataclasses import dataclass
from datetime import datetime
from pandas import DateOffset
from typing import Optional

from sbom_analysis.analyse.metrics import *

logger = logging.getLogger(__name__)


@dataclass
class PackageMetrics:
    """
    Bundles metrics for a single package.
    """

    package_name: str
    downstream_url: Optional[str] = None
    downstream_checkout: Optional[str] = None
    downstream_path: Optional[str] = None
    downstream_primary_lang: Optional[str] = None
    upstream_url: Optional[str] = None
    upstream_checkout: Optional[str] = None
    upstream_primary_lang: Optional[str] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    project_age: Optional[int] = None
    version_age: Optional[int] = None
    project_commits: Optional[int] = None
    project_developers: Optional[int] = None
    loc: Optional[int] = None
    files: Optional[int] = None
    functions: Optional[int] = None
    function_growth: Optional[int] = None
    commits: Optional[int] = None
    commit_trend: Optional[float] = None
    merge_ratio: Optional[float] = None
    bot_ratio: Optional[float] = None
    corrective_count: Optional[int] = None
    corrective_ratio: Optional[float] = None
    churn: Optional[int] = None
    churn_per_function: Optional[float] = None
    churn_trend: Optional[float] = None
    developers: Optional[int] = None
    contributor_trend: Optional[float] = None
    stayers: Optional[int] = None
    stayer_ratio: Optional[float] = None
    core_stayers: Optional[int] = None
    core_stayer_ratio: Optional[float] = None
    leavers: Optional[int] = None
    leaver_ratio: Optional[float] = None
    core_leavers: Optional[int] = None
    core_leaver_ratio: Optional[float] = None
    newcomers: Optional[int] = None
    newcomer_ratio: Optional[float] = None
    pony_factor: Optional[int] = None
    cyclomatic_complexity: Optional[int] = None
    cyclomatic_complexity_per_function: Optional[float] = None
    cyclomatic_complexity_trend: Optional[float] = None
    tokens: Optional[int] = None
    tokens_per_function: Optional[float] = None
    tokens_trend: Optional[float] = None
    cppcheck_errors: Optional[int] = None
    cppcheck_error_density: Optional[float] = None
    cppcheck_error_trend: Optional[float] = None
    cppcheck_warnings: Optional[int] = None
    cppcheck_style_issues: Optional[int] = None
    cppcheck_performance_issues: Optional[int] = None
    cppcheck_portability_issues: Optional[int] = None
    cppcheck_total_issues: Optional[int] = None
    cppcheck_total_issue_density: Optional[float] = None
    cppcheck_cwe_count: Optional[int] = None
    cppcheck_cwe_density: Optional[float] = None
    cppcheck_cwe_trend: Optional[float] = None
    critical_osv_count: Optional[int] = None
    critical_osv_density: Optional[float] = None
    high_osv_count: Optional[int] = None
    medium_osv_count: Optional[int] = None
    low_osv_count: Optional[int] = None
    total_osv_count: Optional[int] = None
    total_osv_density: Optional[float] = None

    def aggregate_commit_metrics(
            self,
            commit_table: DataFrame,
            file_metrics: DataFrame,
            reference_time: datetime,
            window_offset: int,
            window_length: int,
            selected_metrics: list[str]
    ) -> None:
        """
        Aggregate commit-level metrics measuring activity and contributions.

        Args:
            commit_table: DataFrame with analysed commits.
            file_metrics: DataFrame with file-level metrics from lizard.
            reference_time: Reference time for the version checkout.
            window_offset: Time offset in months for the interval of interest.
            window_length: Time interval length in months.
            selected_metrics: List of metrics to calculate.
        """
        if "version_age" in selected_metrics:
            self.version_age = version_age(reference_time)

        if commit_table is None or reference_time is None:
            return

        # Extract relevant time window slices.
        window_end = reference_time - DateOffset(months=window_offset)
        window_start = window_end - DateOffset(months=window_length)
        self.window_start = window_start
        self.window_end = window_end
        commits_window = commit_table[
            (commit_table["committer_date"] > window_start) & (
                commit_table["committer_date"] <= window_end
            )
        ]

        commits_history = commit_table[
            commit_table["committer_date"] <= window_start
        ]

        # Project commits refer to all commits made until the end of the
        # respective window.
        commits_project = commit_table[
            commit_table["committer_date"] <= window_end
        ]

        prev_window_start = window_start - DateOffset(months=window_length)
        commits_prev_window = commit_table[
            (commit_table["committer_date"] > prev_window_start) & (
                    commit_table["committer_date"] <= window_start
            )
        ]

        if "merge_ratio" in selected_metrics:
            self.merge_ratio = merge_ratio(commits_window)

        if "bot_ratio" in selected_metrics:
            self.bot_ratio = bot_ratio(commits_window)

        commit_table = non_bot_commits(commit_table)
        commits_window = non_bot_commits(commits_window)
        commits_history = non_bot_commits(commits_history)
        commits_project = non_bot_commits(commits_project)
        commits_prev_window = non_bot_commits(commits_prev_window)

        # Calculate count-based commit-level metrics.
        if "project_age" in selected_metrics:
            self.project_age = project_age(commits_project, window_end)

        if "commits" in selected_metrics:
            self.commits = commit_count(commits_window)

        if "project_commits" in selected_metrics:
            self.project_commits = commit_count(commits_project)

        if "commit_trend" in selected_metrics:
            self.commit_trend = commit_trend(
                commits_prev_window,
                commits_window
            )

        if "corrective_count" in selected_metrics:
            self.corrective_count = corrective_count(commits_window)

        if "corrective_ratio" in selected_metrics:
            self.corrective_ratio = corrective_ratio(commits_window)

        if "churn" in selected_metrics:
            self.churn = churn(commits_window)

        if "churn_per_function" in selected_metrics:
            self.churn_per_function = churn_per_function(
                commits_window,
                file_metrics
            )

        if "churn_trend" in selected_metrics:
            self.churn_trend = churn_trend(
                commits_prev_window,
                commits_window
            )

        # Calculate count-based metrics related to contributor activity.
        if "developers" in selected_metrics:
            self.developers = developers(commits_window)

        if "project_developers" in selected_metrics:
            self.project_developers = developers(commits_project)

        if "contributor_trend" in selected_metrics:
            self.contributor_trend = contributor_trend(
                commits_prev_window,
                commits_window
            )

        if "stayers" in selected_metrics:
            self.stayers = stayers(commits_prev_window, commits_window)

        if "stayer_ratio" in selected_metrics:
            self.stayer_ratio = stayer_ratio(
                commits_prev_window,
                commits_window
            )

        if "core_stayers" in selected_metrics:
            self.core_stayers = core_stayers(
                commits_prev_window,
                commits_window
            )

        if "core_stayer_ratio" in selected_metrics:
            self.core_stayer_ratio = core_stayer_ratio(
                commits_prev_window,
                commits_window
            )

        if "leavers" in selected_metrics:
            self.leavers = leavers(commits_prev_window, commits_window)

        if "leaver_ratio" in selected_metrics:
            self.leaver_ratio = leaver_ratio(
                commits_prev_window,
                commits_window
            )

        if "core_leavers" in selected_metrics:
            self.core_leavers = core_leavers(
                commits_prev_window,
                commits_window
            )

        if "core_leaver_ratio" in selected_metrics:
            self.core_leaver_ratio = core_leaver_ratio(
                commits_prev_window,
                commits_window
            )

        if "newcomers" in selected_metrics:
            self.newcomers = newcomers(commits_history, commits_window)

        if "newcomer_ratio" in selected_metrics:
            self.newcomer_ratio = newcomer_ratio(
                commits_history,
                commits_window
            )

        if "pony_factor" in selected_metrics:
            self.pony_factor = pony_factor(commits_window)

    def aggregate_lizard_metrics(
            self,
            file_metrics_after: DataFrame,
            file_metrics_before: DataFrame,
            selected_metrics: list[str]
    ) -> None:
        """
        Aggregate code metrics from lizard measuring size and complexity.

        Args:
            file_metrics_after: DataFrame with latest file-level metrics.
            file_metrics_before: DataFrame with past file-level metrics.
            selected_metrics: List of metrics to calculate.
        """
        if "files" in selected_metrics:
            self.files = file_count(file_metrics_after)

        if "functions" in selected_metrics:
            self.functions = function_count(file_metrics_after)

        if "function_growth" in selected_metrics:
            self.function_growth = function_growth(
                file_metrics_before,
                file_metrics_after
            )

        if "loc" in selected_metrics:
            self.loc = loc_count(file_metrics_after)

        if "cyclomatic_complexity" in selected_metrics:
            self.cyclomatic_complexity = cyclomatic_complexity(
                file_metrics_after
            )

        if "cyclomatic_complexity_per_function" in selected_metrics:
            self.cyclomatic_complexity_per_function = cc_per_function(
                file_metrics_after
            )

        if "cyclomatic_complexity_trend" in selected_metrics:
            self.cyclomatic_complexity_trend = cc_trend(
                file_metrics_before,
                file_metrics_after
            )

        if "tokens" in selected_metrics:
            self.tokens = token_count(file_metrics_after)

        if "tokens_per_function" in selected_metrics:
            self.tokens_per_function = tokens_per_function(
                file_metrics_after
            )

        if "tokens_trend"  in selected_metrics:
            self.tokens_trend = tokens_trend(
                file_metrics_before,
                file_metrics_after
            )

    def aggregate_cppcheck_metrics(
            self,
            report_after: DataFrame,
            report_before: DataFrame,
            file_metrics: DataFrame,
            selected_metrics: list[str]
    ) -> None:
        """
        Aggregate static analysis results from cppcheck, which indicate issues
        in the code.

        Args:
            report_after: DataFrame with latest cppcheck issue report.
            report_before: DataFrame with past cppcheck issue report.
            file_metrics: DataFrame with latest file-level metrics.
            selected_metrics: List of metrics to calculate.
        """
        if "cppcheck_errors" in selected_metrics:
            self.cppcheck_errors = cppcheck_issue_count(
                report_after,
                severity="error"
            )

        if "cppcheck_error_density" in selected_metrics:
            self.cppcheck_error_density = cppcheck_issue_density(
                report_after,
                file_metrics,
                severity="error"
            )

        if "cppcheck_error_trend" in selected_metrics:
            self.cppcheck_error_trend = cppcheck_issue_trend(
                report_before,
                report_after,
                severity="error"
            )

        if "cppcheck_warnings" in selected_metrics:
            self.cppcheck_warnings = cppcheck_issue_count(
                report_after,
                severity="warning"
            )

        if "cppcheck_style_issues" in selected_metrics:
            self.cppcheck_style_issues = cppcheck_issue_count(
                report_after,
                severity="style"
            )

        if "cppcheck_performance_issues" in selected_metrics:
            self.cppcheck_performance_issues = cppcheck_issue_count(
                report_after,
                severity="performance"
            )

        if "cppcheck_portability_issues" in selected_metrics:
            self.cppcheck_portability_issues = cppcheck_issue_count(
                report_after,
                severity="portability"
            )

        if "cppcheck_total_issues" in selected_metrics:
            self.cppcheck_total_issues = cppcheck_issue_count(
                report_after
            )

        if "cppcheck_total_issue_density" in selected_metrics:
            self.cppcheck_total_issue_density = cppcheck_issue_density(
                report_after,
                file_metrics
            )

        if "cppcheck_cwe_count" in selected_metrics:
            self.cppcheck_cwe_count = cppcheck_issue_count(
                report_after,
                severity="cwe"
            )

        if "cppcheck_cwe_density" in selected_metrics:
            self.cppcheck_cwe_density = cppcheck_issue_density(
                report_after,
                file_metrics,
                severity="cwe"
            )

        if "cppcheck_cwe_trend" in selected_metrics:
            self.cppcheck_cwe_trend = cppcheck_issue_trend(
                report_before,
                report_after,
                severity="cwe"
            )

    def aggregate_osv_metrics(
            self,
            report: DataFrame,
            file_metrics: DataFrame,
            selected_metrics: list[str]
    ) -> None:
        """
        Aggregate vulnerability statistics queried for a package from the OSV
        database.

        Args:
            report: DataFrame with OSV report.
            file_metrics: DataFrame with latest file-level metrics.
            selected_metrics: List of metrics to calculate.
        """
        if "critical_osv_count" in selected_metrics:
            self.critical_osv_count = osv_count(report, severity="Critical")

        if "critical_osv_density" in selected_metrics:
            self.critical_osv_density = osv_density(
                report,
                file_metrics,
                severity="Critical"
            )

        if "high_osv_count" in selected_metrics:
            self.high_osv_count = osv_count(report, severity="High")

        if "medium_osv_count" in selected_metrics:
            self.medium_osv_count = osv_count(report, severity="Medium")

        if "low_osv_count" in selected_metrics:
            self.low_osv_count = osv_count(report, severity="Low")

        if "total_osv_count" in selected_metrics:
            self.total_osv_count = osv_count(report)

        if "total_osv_density" in selected_metrics:
            self.total_osv_density = osv_density(report, file_metrics)