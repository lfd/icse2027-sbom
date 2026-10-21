# Metrics

The following metrics are calculated for each package in time windows of
`window_months`. The total number of analysed windows depends on the
`history_months` and `shift_months` specified in the configuration file.
Setting `shift_months` to a value <1 or the same value as
`window_months` results in windows which do not overlap.
A shift smaller than `window_months` yields overlapping time windows.
Only full windows are analysed. If a window would be cut off by the end of the
history, it is ignored. This may affect the oldest window within
`history_months`.
Trend metrics always compare full window lengths.

Bot commits, identified
by heuristics, are excluded from all metrics, as they do not represent human
maintenance effort. Merge commits are filtered or kept depending on the metric.
However, both `bot_ratio` and `merge_ratio` can be calculated based on all
commits for context.

### Activity metrics

- `project_age`: Age of the project in months at the end of the time window.
- `version_age`: Number of months since the analysed version of the package
  was released, indicating the exposure time.
- `commits`: Total number of commits (without merges) in the last
  `window_months`. `project_commits` counts all commits *up to* the end of the
  time window.
- `commit_trend`: Activity trend in terms of commits (without merges) in the
  last `window_months` compared to the previous `window_months`.
  Values >1 indicate a growth in activity. Values <1 indicate a reduction. 1
  indicates no change.
- `merge_ratio`: Proportion of merge commits among all commits in the last
  `window_months`.
- `bot_ratio`: Proportion of commits created by bot accounts among all
  commits in the last `window_months`.
- `corrective_count`: Number of commits (without merges) repairing a defect in
  the last `window_months`. A commit is interpreted as corrective if its
  commit summary, i.e. everything up to the first empty line, contains a
  keyword indicating repair. This covers defects of the software and of
  its packaging.
- `corrective_ratio`: Proportion of commits (without merges) repairing a defect
  in the last `window_months`. Values towards 1 indicate that maintenance is
  dominated by repair, values towards 0 that a project spends its effort on
  evolving features.
- `churn`: Total number of lines added and deleted in the last `window_months`
  (without merges).
- `churn_per_function`: Churn normalised by the number of functions in the
  repository (without merges).
- `churn_trend`: Growth trend in churn based on two consecutive time windows
  (without merges). Values >1 indicate a growth in churn. Values <1 indicate a
  reduction. 1 indicates no change.
- `function_growth`: Growth in the absolute number of functions/methods
identified by [lizard](https://github.com/terryyin/lizard) between the latest
snapshot and the snapshot `window_months` ago. Negative values indicate a
reduction. 0 indicates no change.

### Contributor metrics

Contributor metrics all refer to developers *after* identity matching and
bot filtering.

- `developers`: Total number of developers contributing in the last 
`window_months`. `project_developers` counts all developers *up to* the end of
the time window instead.
- `contributor_trend`: Growth trend in the number of developers in the
latest `window_months` compared to the previous `window_months`. Values >1
indicate a growth in contributors. Values <1 indicate a loss. 1 indicates no
change.
- `stayers`: Number of developers from the previous time window who also
contributed in the consecutive `window_months`.
- `stayer_ratio`: Proportion of developers who stayed. Ratio is capped by 1,
meaning that all developers stay.
- `core_stayers`: Number of core developers (top 20% by authored commits,
without merges)
from the previous `window_months` who also contributed in the consecutive
time window.
- `core_stayer_ratio`: Proportion of core developers from the previous
`window_months` who stay in the consecutive time window.
- `leavers`: Number of developers that contributed in the previous
`window_months` but not in the consecutive `window_months`.
- `leaver_ratio`: Proportion of developers from the previous `window_months`
who left in the consecutive `window_months`.
- `core_leavers`: Number of core developers (top 20% by authored commits,
without merges) that
contributed in the previous but not in the consecutive time window.
- `core_leaver_ratio`: Proportion of core developers from the previous
`window_months` who left in the consecutive time window.
- `newcomers`: Number of developers who joined the project in the latest
`window_months` and did not contribute to the project before.
- `newcomer_ratio`: Proportion of developers who joined the project in the
latest `window_months`. Ratio is capped by 1, meaning that the project is only
maintained by newcomers.
- `pony_factor`: Number of developers who authored at least 50% of the
  commits in the last `window_months` (without merges). This is an
  approximation
  of the bus factor indicating the number of developers who own/author/are
  knowledgeable for more than certain proportion of the actual code. Different
  variants for bus factor calculation will be added later.

### Code complexity metrics

These metrics require computationally more expensive analysis with
[lizard](https://github.com/terryyin/lizard).

- `loc`: Total number of source lines of code in the repository at the
latest snapshot. Considers only source code written in languages supported by
[lizard](https://github.com/terryyin/lizard).
- `files`: Total number of files in the repository at the latest snapshot.
Counts all files, including non-source code files.
- `functions`: Total number of functions/methods in the repository at the
latest snapshot.
- `cyclomatic_complexity`: Total cyclomatic complexity (number of linearly
independent paths through the source code) of all code files in the
repository at the latest snapshot.
- `cyclomatic_complexity_per_function`: Cyclomatic complexity normalised by the
number of functions in the repository.
- `cyclomatic_complexity_trend`: Growth trend in cyclomatic complexity between
two consecutive snapshots of a repository. Values >1 indicate a growth in
average complexity. Values <1 indicate a reduction. 1 indicates no change.
- `tokens`: Total number of tokens in the repository at the latest snapshot.
- `tokens_per_function`: Number of tokens normalised by the number of functions
in the repository. Complex packages such as cryptography libraries tend to have
a higher token density.
- `tokens_trend`: Growth trend in the number of tokens between two consecutive
snapshots of a repository. Values >1 indicate a growth in the number of tokens.
Values <1 indicate a reduction. 1 indicates no change.

### Static analysis metrics

The following metrics calculated by
[cppcheck](https://github.com/danmar/cppcheck) for C/C++ files are also
computationally more expensive.

This analysis also invokes [lizard](https://github.com/terryyin/lizard) to
determine files with 0 issues, which would not be reported by cppcheck.
This is important, for instance, if a downstream file fixes an issue of an
upstream file. Test files are excluded from the analysis.

> [!NOTE]
> The cppcheck metrics are currently disabled for the reproduction package.
> If you plan to include them in the analysis, uncomment them in the default
> `metrics` list in
> [config.py](../src/sbom_analysis/config/config.py). 

- `cppcheck_errors`: Total number of issues with `error` severity reported by
[cppcheck](https://cppcheck.sourceforge.io/manual.pdf) for C/C++ files.
This refers to code that is likely to cause undefined behavior or other
errors, such as a memory leak or resource leak, during execution.
- `cppcheck_error_density`: Number of `error` severity issues normalised by
1000 lines of C/C++ code in the repository.
- `cppcheck_error_trend`: Growth trend in the number of issues with `error`
severity in the latest `window_months` compared to the previous
`window_months`. Values >1 indicate a growth in the number of errors. Values <1
indicate a reduction. 1 indicates no change.
- `cppcheck_warnings`: Total number of issues with `warning` severity in
C/C++ files. This refers to code which *may* cause undefined behaviour during
- execution.
- `cppcheck_style_issues`: Total number of issues with `style` severity in
C/C++ files. This refers to stylistic issues, such as unused functions,
redundant code, constness, operator precedence.
- `cppcheck_performance_issues`: Total number of issues with `performance`
severity in C/C++ files. This refers to run time performance suggestions by
[cppcheck](https://cppcheck.sourceforge.io/manual.pdf) based on common
knowledge.
- `cppcheck_portability_issues`: Total number of issues with `portability`
severity reported in C/C++ files. This refers to warnings, for instance related
to 64-bit portability or undefined behaviour.
- `cppcheck_total_issues`: Sum of all of the above issues reported by
[cppcheck](https://cppcheck.sourceforge.io/manual.pdf).
- `cppcheck_total_issue_density`: Total issues normalised by 1000 lines of
C/C++ code in the repository.
- `cppcheck_cwe_count`: Total number of issues reported by
[cppcheck](https://cppcheck.sourceforge.io/manual.pdf) to be related to a
[Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) which is
classified as allowed for automated vulnerability detection.
- `cppcheck_cwe_density`: Number of vulnerability-related issues
normalised by lines of C/C++ code in the repository.
- `cppcheck_cwe_trend`: Growth trend in the number of vulnerability-related
issues in the latest `window_months` compared to the previous `window_months`.
Values >1 indicate a growth in the number of found weaknesses. Values <1
indicate a reduction. 1 indicates no change.

### Vulnerability metrics

These metrics summarise known
[Open-Source Vulnerabilities (OSVs)](https://osv.dev/) by
querying the [OSV database](https://google.github.io/osv.dev/) based on the
package url. We use the
[CVSS Python package](https://github.com/RedHatProductSecurity/cvss) to
determine the severity of each OSV given by the
[Common Vulnerability Scoring System (CVSS) v4.0](https://nvd.nist.gov/vuln-metrics/cvss).
To improve comparability across different versions reported for OSVs, we
consider the overall score in v4.0 or the environmental score if only v3.X is
available. For details on the scoring system, please consult the
[official specification document](https://www.first.org/cvss).

- `critical_osv_count`: Total number of OSVs reported with critical severity.
- `critical_osv_density`: Number of OSVs with critical severity normalised by
1000 lines of code in the repository.
- `high_osv_count`: Total number of OSVs reported with high severity.
- `medium_osv_count`: Total number of OSVs reported with medium severity.
- `low_osv_count`: Total number of OSVs reported with low severity.
- `total_osv_count`: Total number of OSVs, including those with no current
risk.
- `total_osv_density`: Total number of OSVs normalised by 1000 lines of code in
the repository.

### Structural metrics

- `first_degree_dependencies`: Number of other packages directly connected to,
i.e. using or being used by, the package in the dependency graph.
- `transitive_dependencies`: Number of other packages directly or indirectly
connected to the package in the dependency graph.
