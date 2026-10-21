import re

from datetime import datetime, timezone
from pandas import DataFrame

from sbom_analysis.util import TEST_PATH_PATTERNS

# Keywords indicating corrective maintenance, i.e. commits repairing a defect.
# A defect is a deficiency of the delivered work product, so this covers
# defects of the software itself as well as of its packaging, e.g. a failure
# to build from source.
# We use a similar keyword list as the one applied by Commit Guru
# (Rosen et al., FSE 2015, https://doi.org/10.1145/2786805.2803183).
# We removed "patch", because it is also used for non-bug-fixing commits,
# e.g. "patch for new upstream version".
CORRECTIVE_KEYWORDS = [
    "bug", "fix", "error", "fail", "problem", "wrong"
]

# Match the keywords only at the beginning of a word, but tolerate variants
# such as "fixes", "failure" or "bugfix".
# We deliberately avoid substring matching due to false positives, for instance
# "prefix" for "fix" or "dispatch" for "patch".
CORRECTIVE_PATTERN = re.compile(
    r"\b(?:" + "|".join(CORRECTIVE_KEYWORDS) + r")\w*",
    re.IGNORECASE
)

# Identities of common bot accounts committing to the analysed repositories,
# identited by a best-effort approach.
# Important: We match precisely, because words such as "bot", "jenkins" or
# "travis" also occur in the names and addresses of real developers.
BOT_IDENTITIES = [
    r"Debian Janitor",
    r"debian-janitor@",
    r"<janitor@jelmer\.uk>",
    r"D-I role",
    r"debian-installer role",
    r"l10n Commit Robot",
    r"usd-importer",
    r"git-ubuntu importer",
    r"Ubuntu Git Importer",
    r"USD Importer",
    r"<jenkins@jenkins\.debian\.net>",
    r"\[bot\]",
    r"dependabot",
    r"renovate-?bot",
    r"github-actions",
    r"semantic-release",
    r"rustbot",
    r"@cron\.bot",
    r"@weblate\.org",
    r"GitHub <noreply@github\.com>"
]

BOT_PATTERN = re.compile("|".join(BOT_IDENTITIES), re.IGNORECASE)


def project_age(
        commit_table: DataFrame | None,
        reference_date: str | None = None
) -> int | None:
    """
    Calculate the age of the project in months based on the commit table.

    Args:
        commit_table: DataFrame with commit data.
        reference_date: Date to calculate the age of the project relative to.
            If None, use the latest commit date.

    Returns:
        The age of the project in months.
    """
    if commit_table is None or len(commit_table) == 0:
        return None

    if reference_date is None:
        reference_date = commit_table["committer_date"].max()

    start_date = commit_table["committer_date"].min()
    age_months = (reference_date.year - start_date.year) * 12 + (
            reference_date.month - start_date.month)
    return age_months


def version_age(
        reference_date,
        analysis_date=None
) -> int | None:
    """
    Calculate for how many months the analysed version of a package has been
    released.

    The version is dated by the commit which the analysis checked out, as the
    package of a release is frozen at that state and known vulnerabilities
    accumulate over time.

    Args:
        reference_date: Date of the analysed version.
        analysis_date: Date to calculate the age relative to, or None for the
            current date.

    Returns:
        The age of the version in months.
    """
    if reference_date is None:
        return None

    if analysis_date is None:
        analysis_date = datetime.now(timezone.utc)

    return (analysis_date.year - reference_date.year) * 12 + (
            analysis_date.month - reference_date.month)


def non_merge_commits(commit_table: DataFrame | None) -> DataFrame | None:
    """
    Get the commits which are not merges.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The commit table without merge commits.
    """
    if commit_table is None:
        return None

    return commit_table[~commit_table["is_merge"].astype(bool)]


def non_bot_commits(commit_table: DataFrame | None) -> DataFrame | None:
    """
    Get the commits which were not created by bot accounts. Bots do not
    represent human maintenance effort.

    Important: Identifying bots by their identity is a best-effort approach.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The commit table without commits of bot accounts.
    """
    if commit_table is None:
        return None

    # Search for bot accounts in the identity columns.
    bots = commit_table["author"].fillna("").astype(str).str.contains(
        BOT_PATTERN
    ) | commit_table["committer"].fillna("").astype(str).str.contains(
        BOT_PATTERN
    )
    return commit_table[~bots]


def bot_ratio(commit_table: DataFrame | None) -> float | None:
    """
    Calculate the proportion of commits created by bot accounts.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The proportion of commits of automated accounts.
    """
    if commit_table is None or len(commit_table) == 0:
        return None

    bots = len(commit_table) - len(non_bot_commits(commit_table))
    return bots / len(commit_table)


def commit_count(commit_table: DataFrame | None) -> int | None:
    """
    Calculate the total number of development commits in the commit table.

    Merge commits are excluded, as they represent integration rather than
    actual development activity.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The number of commits.
    """
    if commit_table is None:
        return None

    return len(non_merge_commits(commit_table))


def commit_trend(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the commit activity trend. Values >1 indicate an increased
    activity. Values <1 indicate a decrease. 1 indicates no change.

    Merge commits are excluded, as they represent integration rather than
    actual development efforts.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The commit activity trend, or None if there are no commits for
        comparison.
    """
    before = non_merge_commits(commits_before)
    if len(before) == 0:
        return None

    after = non_merge_commits(commits_after)

    return len(after) / len(before)


def merge_ratio(commit_table: DataFrame | None) -> float | None:
    """
    Calculate the proportion of merge commits.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The proportion of merge commits.
    """
    if commit_table is None or len(commit_table) == 0:
        return None

    merges = commit_table["is_merge"].astype(bool)
    return float(merges.sum()) / len(commit_table)


def corrective_count(commit_table: DataFrame | None) -> int | None:
    """
    Calculate the number of commits performing corrective maintenance, i.e.
    repairing a defect. A commit is interpreted as corrective if the commit
    summary contains one of the keywords indicating corrective maintenance.

    Defects may affect both the software itself and its packaging.

    We deliberately excluded the commit message body because keyword-based
    matching could lead to many false positives.

    Important: Keyword-based classification is a best-effort approach.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The number of corrective commits.
    """
    if commit_table is None or "commit_message" not in commit_table:
        return None

    # Filter merge commits, as they represent integration rather than actual
    # corrective efforts.
    commits = non_merge_commits(commit_table)

    # Commits without a message and empty commit tables must be cast
    # explicitly, as their column is not of string type.
    messages = commits["commit_message"].fillna("").astype(str)

    # Only match the commit summary, i.e. everything up to the first empty
    # line, and ignore the message body. Bodies frequently list changelog
    # entries or discuss the defects of other commits, which would classify
    # imports of a new upstream version and similar commits as corrective.
    summaries = messages.str.split("\n\n", n=1).str[0]
    return int(summaries.str.contains(CORRECTIVE_PATTERN).sum())


def corrective_ratio(commit_table: DataFrame | None) -> float | None:
    """
    Calculate the proportion of commits performing corrective maintenance.
    Values towards 1 indicate that maintenance is dominated by repair, values
    towards 0 that a project spends its effort on evolving its features.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The proportion of corrective commits.
    """
    if commit_table is None or "commit_message" not in commit_table:
        return None

    fixes = corrective_count(commit_table)
    commits = len(non_merge_commits(commit_table))
    return fixes / commits if commits > 0 else None


def churn(commit_table: DataFrame | None) -> int | None:
    """
    Calculate the number of added and deleted lines in the commit table.

    Merge commits are excluded, as their combined diff repeats the changes of
    the branch they integrate and would count them twice.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The total churn.
    """
    if commit_table is None:
        return None

    commits = non_merge_commits(commit_table)
    return sum(commits["added"].values) + sum(commits["removed"].values)


def developers(commit_table: DataFrame | None) -> int | None:
    """
    Calculate the number of developers who contributed according to the commit
    table.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The number of developers.
    """
    if commit_table is None:
        return None

    return len(developer_set(commit_table))


def contributor_trend(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the contributor activity trend. Values >1 indicate a growth in
    contributors. Values <1 indicate a loss. 1 indicates no change.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The contributor base growth ratio, or None if there are no contributors
        to compare.
    """
    devs_before = set(commits_before[["author", "committer"]].stack())
    if len(devs_before) == 0:
        return None
    else:
        devs_after = set(commits_after[["author", "committer"]].stack())
        return len(devs_after) / len(devs_before)


def developer_set(commit_table: DataFrame | None) -> set | None:
    """
    Get the unique developer identities in the commit table.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The set of unique developer identities.
    """
    if commit_table is None:
        return None

    return set(commit_table[["author", "committer"]].stack().dropna())


def core_developer_set(commit_table: DataFrame | None) -> set | None:
    """
    Get the unique core developer identities in the commit table. Interpret
    core developers as the top 20% of developers according to the number of
    commits they authored.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The set of unique core developer identities.
    """
    if commit_table is None:
        return None

    commits = non_merge_commits(commit_table)
    dev_commit_counts = commits["author"].dropna().value_counts()
    if len(dev_commit_counts) == 0:
        return set()

    core_dev_idx = max(1, int(len(dev_commit_counts) * 0.2))
    return set(dev_commit_counts.head(core_dev_idx).index)


def stayers(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> int | None:
    """
    Calculate the number of stayers, i.e., developers who contributed in two
    consecutive time intervals.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The number of stayers.
    """
    devs_before = developer_set(commits_before)
    if len(devs_before) == 0:
        return None

    devs_after = developer_set(commits_after)
    devs_both = devs_after & devs_before
    return len(devs_both)


def stayer_ratio(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculates the stayers ratio of developers. Stayer ratio is capped by 1,
    meaning that all developers stay active.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The stayers ratio.
    """
    devs_before = developer_set(commits_before)
    if len(devs_before) == 0:
        return None

    devs_after = developer_set(commits_after)
    devs_both = devs_after & devs_before
    return len(devs_both) / len(devs_before)


def core_stayers(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> int | None:
    """
    Calculate the number of stayers among core developers. Interpret core
    developers as the top 20% of developers according to the number of
    commits they authored.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The number of core stayers.
    """
    core_before = core_developer_set(commits_before)
    if len(core_before) == 0:
        return None

    devs_after = developer_set(commits_after)
    core_after = devs_after & core_before
    return len(core_after)


def core_stayer_ratio(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the stayers ratio of core developers. Interpret core developers
    as the top 20% of developers according to the number of commits they
    authored. Ratio is capped by 1, meaning that all core developers stay.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The core stayers ratio.
    """
    core_before = core_developer_set(commits_before)
    devs_after = developer_set(commits_after)
    core_both = devs_after & core_before
    return len(core_both) / len(core_before) if len(core_before) > 0 else None


def leavers(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> int | None:
    """
    Calculate the number of leavers, i.e., developers who contributed in the
    first time interval but not in the second.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The number of leavers.
    """
    devs_before = developer_set(commits_before)
    devs_after = developer_set(commits_after)
    devs_leave = devs_before - devs_after
    return len(devs_leave)


def leaver_ratio(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the leavers ratio of developers. Leaver ratio is capped by 1,
    meaning that all developers leave.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The leavers ratio.
    """
    devs_before = developer_set(commits_before)
    devs_after = developer_set(commits_after)
    devs_leave = devs_before - devs_after
    return len(devs_leave) / len(devs_before) if len(devs_before) > 0 else None


def core_leavers(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> int | None:
    """
    Calculate the number of leavers among core developers. Interpret core
    developers as the top 20% of developers according to the number of
    commits they authored.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The number of core leavers.
    """
    core_before = core_developer_set(commits_before)
    devs_after = developer_set(commits_after)
    core_leave = core_before - devs_after
    return len(core_leave)


def core_leaver_ratio(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the leavers ratio of core developers. Interpret core developers
    as the top 20% of developers according to the number of commits they
    authored. Ratio is capped by 1, meaning that all core developers leave.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The core leavers ratio.
    """
    core_before = core_developer_set(commits_before)
    devs_after = developer_set(commits_after)
    core_leave = core_before - devs_after
    return len(core_leave) / len(core_before) if len(core_before) > 0 else None


def newcomers(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> int | None:
    """
    Calculate the number of newcomers, i.e., developers who did not contribute
    in the past.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The number of newcomers.
    """
    devs_before = developer_set(commits_before)
    devs_after = developer_set(commits_after)
    devs_newc = devs_after - devs_before
    return len(devs_newc)


def newcomer_ratio(
        commits_before: DataFrame,
        commits_after: DataFrame
) -> float | None:
    """
    Calculate the newcomers ratio of developers. Newcomer ratio is capped by 1,
    meaning that all current developers are newcomers.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The newcomers ratio.
    """
    devs_before = developer_set(commits_before)
    devs_after = developer_set(commits_after)
    devs_newc = devs_after - devs_before
    return len(devs_newc) / len(devs_after) if len(devs_after) > 0 else None


def pony_factor(commit_table: DataFrame | None) -> int | None:
    """
    Calculate the pony factor, i.e., the number of developers who authored
    more than 50% of commits in the time interval. This is a rough
    approximation of the bus factor, which considers the number of developers
    whose absence would cause a project to fail or stall. (Contrary to the pony
    factor, the bus factor is calculated based on actual code
    authorship/ownership to represent knowledge about the code base.)

    Merge commits are excluded, as they are attributed to the developer who
    integrated a change rather than to its author, which would distort the code
    ownership approximated here.

    Args:
        commit_table: DataFrame with commit data.

    Returns:
        The pony factor.
    """
    if commit_table is None:
        return None

    commits = non_merge_commits(commit_table)

    if len(commits) == 0:
        return 0
    else:
        thresh = len(commits) / 2
        agg = (
            commits.groupby("author", as_index=False)["commit_hash"]
            .count()
            .rename(columns={"commit_hash": "commit_count"})
            .sort_values("commit_count", ascending=False)
        )
        agg["cum_count"] = agg["commit_count"].cumsum()
        idx = (agg["cum_count"] >= thresh).idxmax()
        return len(agg.loc[:idx])


def file_count(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the total number of code files in the repository.

    Args:
        file_metrics: DataFrame with file-level metrics.

    Returns:
        The number of files.
    """
    if file_metrics is None:
        return None

    return len(file_metrics["file_path"].unique())


def function_count(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the total number of functions in all code files in the
    repository.

    Args:
        file_metrics: DataFrame with file-level metrics.

    Returns:
        The number of functions.
    """
    if file_metrics is None:
        return None

    return sum(file_metrics["functions"])


def loc_count(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the total number of lines of code in all code files in the
    repository.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The number of lines of code.
    """
    if file_metrics is None:
        return None

    return sum(file_metrics["loc"])


def cloc_count(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the number of C/C++ lines of code in all code files in the
    repository.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The number of C/C++ lines of code.
    """
    if file_metrics is None:
        return None

    file_endings = [".c", ".h", ".cpp", ".cc", ".cxx", ".C", ".hpp", ".hh",
                    ".hxx"]
    c_file_metrics = file_metrics[file_metrics["file_path"].str.endswith(
        tuple(file_endings))]
    return sum(c_file_metrics["loc"])


def churn_per_function(
        commit_table: DataFrame | None,
        file_metrics: DataFrame | None
) -> float | None:
    """
    Calculate the churn density as the number of added and deleted lines
    normalised by the number of functions in the repository.

    Args:
        commit_table: DataFrame with commit data.
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The average churn per function.
    """
    if file_metrics is None:
        return None

    c = churn(commit_table)
    f = function_count(file_metrics)
    return c / f if f > 0 else None


def churn_trend(
        commits_before: DataFrame,
        commits_after: DataFrame,
) -> float | None:
    """
    Calculate the churn trend. Values >1 indicate an increase in average churn.
    Values <1 indicate a decrease. 1 indicates no change.

    Args:
        commits_before: DataFrame with commits before the cutoff date.
        commits_after: DataFrame with commits after the cutoff date.

    Returns:
        The churn trend, or None if the previous time window holds no churn to
        compare to.
    """
    if len(commits_before) == 0:
        return None

    c_before = churn(commits_before)
    c_after = churn(commits_after)
    return c_after / c_before if c_before > 0 else None


def cyclomatic_complexity(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the total cyclomatic complexity in all code files in the
    repository.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The cyclomatic complexity.
    """
    if file_metrics is None:
        return None

    return sum(file_metrics["cyclomatic_complexity"])


def cc_per_function(file_metrics: DataFrame | None) -> float | None:
    """
    Calculate the cyclomatic complexity density as the total cyclomatic
    complexity normalised by the project size in number of functions.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The average cyclomatic complexity per function.
    """
    if file_metrics is None:
        return None

    cc = cyclomatic_complexity(file_metrics)
    f = function_count(file_metrics)
    return cc / f if f > 0 else None


def cc_trend(
        file_metrics_before: DataFrame | None,
        file_metrics_after: DataFrame | None
) -> float | None:
    """
    Calculate the growth trend in cyclomatic complexity between two consecutive
    snapshots of a repository. Values >1 indicate a growth in cyclomatic
    complexity. Values <1 indicate a reduction. 1 indicates no change.

    Args:
        file_metrics_before: DataFrame with past file-level metrics from
            lizard.
        file_metrics_after: DataFrame with latest file-level metrics from
            lizard.

    Returns:
        The growth ratio of cyclomatic complexity, or None if there aren't any
        numbers to compare.
    """
    # A missing snapshot means that the code was not analysed, which must not
    # be reported as a complexity of zero.
    if file_metrics_before is None or file_metrics_after is None:
        return None

    cc_before = cyclomatic_complexity(file_metrics_before)
    cc_after = cyclomatic_complexity(file_metrics_after)
    return cc_after / cc_before if cc_before > 0 else None


def token_count(file_metrics: DataFrame | None) -> int | None:
    """
    Calculate the total number of tokens in all code files in the repository.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The number of tokens.
    """
    if file_metrics is None:
        return None

    return sum(file_metrics["tokens"])


def tokens_per_function(file_metrics: DataFrame | None) -> float | None:
    """
    Calculate the token density as the total number of tokens normalised by the
    project size in number of functions.

    Args:
        file_metrics: DataFrame with file-level metrics from lizard.

    Returns:
        The average token density per function.
    """
    if file_metrics is None:
        return None

    t = token_count(file_metrics)
    f = function_count(file_metrics)
    return t / f if f > 0 else None


def tokens_trend(
        file_metrics_before: DataFrame | None,
        file_metrics_after: DataFrame | None
) -> float | None:
    """
    Calculate the growth trend in number of tokens between two consecutive
    snapshots of a repository. Values >1 indicate a growth in number of
    tokens. Values <1 indicate a reduction. 1 indicates no change.

    Args:
        file_metrics_before: DataFrame with past file-level metrics from
            lizard.
        file_metrics_after: DataFrame with latest file-level metrics from
            lizard.

    Returns:
        The growth trend of number of tokens, or None if one of the snapshots
        was not analysed.
    """
    if file_metrics_before is None or file_metrics_after is None:
        return None

    t_before = token_count(file_metrics_before)
    t_after = token_count(file_metrics_after)
    return t_after / t_before if t_before > 0 else None


def function_growth(
        file_metrics_before: DataFrame | None,
        file_metrics_after: DataFrame | None
) -> int | None:
    """
    Calculate the growth trend in number of functions between two consecutive
    snapshots of a repository.

    Args:
        file_metrics_before: DataFrame with past file-level metrics from
            lizard.
        file_metrics_after: DataFrame with latest file-level metrics from
            lizard.

    Returns:
        The growth in number of functions.
    """
    if file_metrics_after is None:
        return None

    if file_metrics_before is None:
        return function_count(file_metrics_after)

    functions_latest = function_count(file_metrics_after)
    functions_past = function_count(file_metrics_before)
    return functions_latest - functions_past


def cppcheck_issue_count(
        report: DataFrame | None,
        severity: str = None
) -> int | None:
    """
    Calculate the total number of issues (of a certain severity level) in a
    cppcheck report.

    Args:
        report: DataFrame with the cppcheck report.
        severity: Severity level to filter by.

    Returns:
        The total number of issues with the specified severity.
    """
    if report is None:
        return None

    if severity == "cwe":
        cwe_df = report[report["cwe"].notna()]
        return len(cwe_df[cwe_df["mapping"] == "Allowed"])
    if severity is None:
        return len(report)

    return len(report[report["severity"] == severity])


def cppcheck_issue_density(
        report: DataFrame | None,
        file_metrics: DataFrame | None,
        severity: str = None
) -> float | None:
    """
    Calculate the issue density as the number of issues (of a certain
    severity level) normalised by the project size in 1000 C/C++ lines of code.

    Test code is excluded from the project size to match the behaviour of
    cppcheck in the CodeAnalyser, which does not report issues for it.

    Args:
        report: DataFrame with the cppcheck report.
        file_metrics: DataFrame with file-level metrics from lizard.
        severity: Severity level to filter by.

    Returns:
        The issue density of specified severity.
    """
    if report is None:
        return None

    if file_metrics is None:
        return None

    # Consider only the files analysed by cppcheck to ensure that the density
    # is related to the code the issues for were reported for.
    analysed_files = file_metrics[~file_metrics["file_path"].str.contains(
        TEST_PATH_PATTERNS, na=False
    )]

    issues = cppcheck_issue_count(report, severity=severity)
    cloc = cloc_count(analysed_files)
    return issues / (cloc/1000) if cloc > 0 else None


def cppcheck_issue_trend(
        report_before: DataFrame | None,
        report_after: DataFrame | None,
        severity: str
) -> float | None:
    """
    Calculate the growth trend of issues (of a certain severity) between two
    consecutive snapshots of a repository. Values >1 indicate a growth in
    issues. Values <1 indicate a reduction. 1 indicates no change.

    Args:
        report_before: DataFrame with the past cppcheck report.
        report_after: DataFrame with the latest cppcheck report.
        severity: Severity level to filter by.

    Returns:
        The growth ratio of issues with the specified severity, or None if one
        of the reports is missing.
    """
    if report_before is None or report_after is None:
        return None

    issues_before = cppcheck_issue_count(report_before, severity)
    issues_after = cppcheck_issue_count(report_after, severity)
    return issues_after / issues_before if issues_before > 0 else None


def osv_count(
        report: DataFrame | None,
        severity: str = None
) -> int | None:
    """
    Calculate the total number of OSVs (of a certain severity level) in the
    report.

    Args:
        report: DataFrame with the OSV report.
        severity: Severity level to filter by.

    Returns:
        The total number of OSVs with the specified severity.
    """
    if report is None:
        return None

    if severity is None:
        return len(report)

    return len(report[report["severity_class"] == severity])


def osv_density(
        report: DataFrame | None,
        file_metrics: DataFrame | None,
        severity: str = None
) -> float | None:
    """
    Calculate the OSV density as the number of OSVs (of a certain severity
    level) normalised by the project size in 1000 C/C++ lines of code.

    Args:
        report: DataFrame with the OSV report.
        file_metrics: DataFrame with file-level metrics from lizard.
        severity: Severity level to filter by.

    Returns:
        The OSV density of specified severity.
    """
    if report is None:
        return None

    if file_metrics is None:
        return None

    osv = osv_count(report, severity=severity)
    loc = loc_count(file_metrics)
    return osv / (loc/1000) if loc > 0 else None
