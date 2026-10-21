import csv
import logging
import math
import shutil
import subprocess

from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from git import Repo
from lizard import analyze_file
from os import listdir, path, makedirs, walk
from pandas import DataFrame, concat, read_csv, DateOffset
from xml.etree import ElementTree as ET

from sbom_analysis.config.config import PackageInfo, monorepo_downstreams
from sbom_analysis.util import (analysis_dir_name, analysis_windows,
                                checkout_version, get_api_data,
                                repo_dir_name, safe_read_csv,
                                TEST_PATH_PATTERNS)

logger = logging.getLogger(__name__)


def _setup_worker_logging(level: int) -> None:
    """
    Configure logging in a worker process analysing a repository.

    Depending on the platform, worker processes are spawned instead of forked
    and therefore do not inherit the logging configuration of the main
    process. Without this, their messages would be lost.

    Args:
        level: Logging level configured for the main process.
    """
    logging.basicConfig(level=level)


class CodeAnalyser:
    """
    Calculates metrics with code analysis tools based on snapshots of
    repository files.
    """

    FILE_EXT = [
        ".cs", ".csx", ".cake", ".cshtml", ".razor",
        ".c", ".h", ".cpp", ".cc", ".cxx", ".C", ".hpp", ".hh", ".hxx",
        ".erl", ".hrl",
        ".f", ".for", ".f77", ".f90", ".f95", ".f03", ".f08", ".fpp",
        ".gd", ".gdscript",
        ".go",
        ".java",
        ".js", ".mjs", ".cjs", ".jsx",
        ".kt", ".kts",
        ".lua",
        "makefile", "Makefile", ".mk", ".mak", ".make", ".cmake",
        ".m", ".mm",
        ".pl", ".pm", ".t",
        ".php", ".phtml", ".php3", ".php4", ".php5", ".inc",
        ".sql", ".pls", ".pks", ".pkb",
        ".py", ".pyw", ".pyi",
        ".r", ".R", ".Rmd",
        ".rb", ".erb", ".rake",
        ".rs",
        ".scala", ".sc",
        ".sh", ".bash", ".zsh", ".bashrc",
        ".sol",
        ".st", ".scl",
        ".swift",
        ".ttcn3", ".ttcn",
        ".ts", ".tsx",
        ".vue",
        ".zig"
    ]

    def _calculate_lizard_metrics(
            self,
            res_name: str,
            repo_path: str,
            analysis_path: str,
            repo_type: str,
            window: str
    ) -> None:
        """
        Calculate code metrics using lizard for all code files and contained
        functions in the repository.

        Args:
            res_name: Name of the analysed repository version.
            repo_path: Path to the repository to analyse.
            analysis_path: Path to store lizard code metrics.
            repo_type: Type of repository to analyse (down or up).
            window: Temporal snapshot identifier.
        """
        makedirs(analysis_path, exist_ok=True)
        file_path = path.join(
            analysis_path, f"file_metrics_{repo_type}_{window}.csv"
        )
        func_path = path.join(
            analysis_path, f"function_metrics_{repo_type}_{window}.csv"
        )

        if path.exists(file_path) and path.exists(func_path):
            logger.info(
                f"Lizard metrics for {res_name} ({repo_type}, window "
                f"{window}) already exist. Skipping."
            )
            return

        with open(file_path, "w", newline="", encoding="utf-8") as file_table, \
            open(func_path, "w", newline="", encoding="utf-8") as func_table:
            file_cols = [
                "file_path",
                "loc",
                "functions",
                "tokens",
                "cyclomatic_complexity"
            ]
            file_writer = csv.DictWriter(file_table,
                                         fieldnames=file_cols)
            file_writer.writeheader()
            function_cols = [
                "file_path",
                "function",
                "parameters",
                "loc",
                "tokens",
                "cyclomatic_complexity"
            ]
            function_writer = csv.DictWriter(func_table,
                                             fieldnames=function_cols)
            function_writer.writeheader()

            # Iterate all files in the repository to calculate code metrics at
            # file level and function level for all code files.
            for root, dirs, files in walk(repo_path):
                # Skip the git database, which is not part of the source tree
                # and would be counted as files of the repository otherwise.
                dirs[:] = [d for d in dirs if d != ".git"]

                for file in files:
                    analysis_file_path = path.join(root, file)
                    if any(analysis_file_path.endswith(end) for end
                           in self.FILE_EXT):
                        analysis_result = analyze_file(analysis_file_path)
                        cc = 0
                        for func in analysis_result.function_list:
                            function_entry = {
                                "file_path": analysis_file_path,
                                "function": func.__dict__["name"],
                                "parameters":
                                    len(func.__dict__["full_parameters"]),
                                "loc": func.__dict__["nloc"],
                                "tokens": func.__dict__["token_count"],
                                "cyclomatic_complexity":
                                    func.__dict__["cyclomatic_complexity"]
                            }
                            function_writer.writerow(function_entry)
                            cc += func.__dict__["cyclomatic_complexity"]

                        file_entry = {
                            "file_path": analysis_file_path,
                            "loc": analysis_result.__dict__["nloc"],
                            "functions": len(analysis_result.function_list),
                            "tokens": analysis_result.__dict__["token_count"],
                            "cyclomatic_complexity": cc
                        }
                        file_writer.writerow(file_entry)
                    else:
                        file_entry = {
                                "file_path": analysis_file_path,
                                "loc": 0,
                                "functions": 0,
                                "tokens": 0,
                                "cyclomatic_complexity": 0
                            }
                        file_writer.writerow(file_entry)

    @staticmethod
    def _results_exist(
            lizard_path: str,
            cppcheck_path: str,
            repo_type: str,
            window: int,
            lizard_analysis: bool,
            cppcheck_analysis: bool
    ) -> bool:
        """
        Check whether all required results of a snapshot already exist.

        Args:
            lizard_path: Path to the lizard results of the repository version.
            cppcheck_path: Path to the cppcheck results of the repository
                version.
            repo_type: Type of the analysed repository (down or up).
            window: Temporal snapshot identifier.
            lizard_analysis: Whether lizard analysis is required.
            cppcheck_analysis: Whether cppcheck analysis is required.

        Returns:
            True if no analysis is required for the snapshot, False otherwise.
        """
        results = []
        if lizard_analysis:
            results += [
                path.join(
                    lizard_path, f"file_metrics_{repo_type}_{window}.csv"
                ),
                path.join(
                    lizard_path, f"function_metrics_{repo_type}_{window}.csv"
                )
            ]
        if cppcheck_analysis:
            results.append(
                path.join(cppcheck_path, f"report_{repo_type}_{window}.csv")
            )

        return bool(results) and all(path.exists(r) for r in results)

    def _analyse_repo(
            self,
            repo_path: str,
            snapshots: list[tuple[str, str, str]],
            analysis_dir: str,
            windows: dict[int, int],
            lizard_analysis: bool,
            cppcheck_analysis: bool
    ) -> None:
        """
        Analyse all versions of a repository which the packages refer to.

        The repository is the unit of parallel work, because checking out a
        version modifies its working tree.

        Args:
            repo_path: Path to the repository to analyse.
            snapshots: Repository type, checkout and result directory name of
                the versions to analyse.
            analysis_dir: Directory where the analysis results will be stored.
            windows: Time windows to analyse and their offset in months.
            lizard_analysis: Whether lizard analysis is required.
            cppcheck_analysis: Whether cppcheck analysis is required.
        """
        # The repository is opened here, as it cannot be passed to a worker.
        repo = Repo(repo_path)
        latest_window = max(windows) if windows else None

        for repo_type, checkout, res_name in snapshots:
            lizard_path = path.join(analysis_dir, "lizard", "repos", res_name)
            cppcheck_path = path.join(
                analysis_dir, "cppcheck", "repos", res_name
            )

            # Past snapshots refer to a date relative to the date of the
            # version, which is the same for all windows.
            commit_date = repo.commit(checkout).committed_datetime

            # Iterate over time windows to analyse multiple snapshots of
            # the repository.
            for w, offset in windows.items():
                if self._results_exist(
                        lizard_path, cppcheck_path, repo_type, w,
                        lizard_analysis, cppcheck_analysis
                ):
                    logger.info(
                        f"Results for {res_name} ({repo_type}, window {w}) "
                        f"already exist. Skipping."
                    )
                    continue

                if w == latest_window:
                    # Check out the repository at the correct version branch,
                    # tag or commit as specified in the configuration file.
                    checkout_version(repo, checkout)
                else:
                    window_start_date = commit_date - \
                                        DateOffset(months=offset)

                    # Search for the closest commit in the repository
                    # before that date. For code analysis, it is acceptable
                    # if that commit lies in an even earlier time window,
                    # as with no commits in the window in the window of
                    # interest, the repository state is likely to be the
                    # same. The version is passed explicitly, as the
                    # repository is left at the snapshot analysed before.
                    commit = next(
                        ( c for c in repo.iter_commits(checkout)
                          if datetime.fromtimestamp(
                            c.committed_date,
                            tz=timezone.utc) <= window_start_date
                          ),
                        None  # If no commit is found, return None.
                    )
                    if commit is None:
                        # If there is no past commit, we know that the
                        # repository itself is newer than the time window
                        # of interest, so we can skip past analyses.
                        continue

                    # Force checkout in case any unwanted changes were
                    # made before.
                    commit_hash_past = commit.hexsha
                    checkout_version(repo, commit_hash_past)

                # Analyse code in the latest state of the repository.
                if lizard_analysis:
                    logger.info(
                        f"Analysing {res_name} (window {w}) with lizard..."
                    )
                    self._calculate_lizard_metrics(
                        res_name,
                        repo_path,
                        lizard_path,
                        repo_type,
                        str(w)
                    )
                if cppcheck_analysis:
                    logger.info(
                        f"Analysing {res_name} (window {w}) with cppcheck..."
                    )
                    self._calculate_cppcheck_metrics(
                        res_name,
                        repo_path,
                        cppcheck_path,
                        repo_type,
                        str(w)
                    )

    @staticmethod
    def _clean_results(
            analysis_dir: str,
            snapshots: list[tuple[str, str, str]],
            error: Exception
    ) -> None:
        """
        Discard the code analysis results of a repository which could not be
        analysed completely.

        Results are reused if they exist, so incomplete results must be
        removed. Otherwise, the next run would keep them and calculate
        metrics from a partially analysed repository.

        Args:
            analysis_dir: Directory where the analysis results are stored.
            snapshots: Repository type, checkout and result directory name of
                the versions which were analysed.
            error: Error which interrupted the analysis.
        """
        logger.warning(
            "Code analysis failed for repository %s. Discarding results.",
            snapshots[0][2] if snapshots else "unknown"
        )
        logger.debug(error, exc_info=True)

        for _, _, res_name in snapshots:
            for tool in ("lizard", "cppcheck"):
                shutil.rmtree(
                    path.join(analysis_dir, tool, "repos", res_name),
                    ignore_errors=True
                )

    @staticmethod
    def _test_paths(repo_path: str) -> list[str]:
        """
        Identify test files and directories of a repository.

        We use a custom pattern instead of cppcheck's option for accuracy.

        Args:
            repo_path: Path to the repository to analyse.

        Returns:
            The paths of the test files and directories.
        """
        test_paths = []
        for root, dirs, files in walk(repo_path):
            tests = [d for d in dirs if TEST_PATH_PATTERNS.search(d)]

            # Do not descend into .git or test directories, as their content is
            # excluded with them.
            dirs[:] = [
                d for d in dirs if d not in tests and d != ".git"
            ]

            test_paths += [path.join(root, d) for d in tests]
            test_paths += [
                path.join(root, f) for f in files
                if TEST_PATH_PATTERNS.search(f)
            ]

        return test_paths

    @staticmethod
    def _calculate_cppcheck_metrics(
            res_name: str,
            repo_path: str,
            analysis_path: str,
            repo_type: str,
            window: str
    ) -> None:
        """
        Calculate code metrics using cppcheck for the project repository.

        Args:
            res_name: Name of the analysed repository version.
            repo_path: Path to the repository to analyse.
            analysis_path: Path to store code issue metrics.
            repo_type: Type of repository to analyse (down or up).
            window: Temporal snapshot identifier.
        """
        makedirs(analysis_path, exist_ok=True)
        file_path = path.join(
            analysis_path, f"report_{repo_type}_{window}.csv"
        )

        if path.exists(file_path):
            logger.info(
                f"Cppcheck reports for {res_name} ({repo_type}, window "
                f"{window}) already exist. Skipping."
            )
            return

        build_dir = path.join(analysis_path, "build")
        makedirs(build_dir, exist_ok=True)
        xml_path = path.join(analysis_path, f"report_{repo_type}_{window}.xml")
        csv_path = path.join(analysis_path, f"report_{repo_type}_{window}.csv")

        # Determine test paths to ignore.
        ignored = [
            arg for test_path in CodeAnalyser._test_paths(repo_path)
            for arg in ("-i", test_path)
        ]

        try:
            # Run cppcheck on the repository.
            cmd = [
                "cppcheck",
                "--xml", # Generate XML output.
                "--enable=all", # Enable all checks with high sensitivity.
                *ignored,
                f"--cppcheck-build-dir={build_dir}",
                f"--output-file={xml_path}",
                repo_path
            ]
            subprocess.check_output(cmd, stderr=subprocess.DEVNULL)

            # If the repository did not contain C/C++ code, cppcheck may not
            # have generated a report.
            if not path.exists(xml_path):
                return

            # Parse XML report generated by cppcheck and convert it to CSV.
            with open(
                    csv_path, "w", newline="", encoding="utf-8"
            ) as report_table:
                cols = ["file_path", "line", "column", "severity", "id", "cwe"]
                writer = csv.DictWriter(report_table, fieldnames=cols)
                writer.writeheader()

                root = ET.parse(xml_path).getroot()
                for error in root.findall("./errors/error"):
                    if error.get("severity") == "information":
                        # Ignore information messages.
                        continue

                    entry = {
                        "file_path": error.find("location").get("file"),
                        "line": error.find("location").get("line"),
                        "column": error.find("location").get("column"),
                        "severity": error.get("severity"),
                        "id": error.get("id"),
                        "cwe": error.get("cwe") or ""
                    }
                    writer.writerow(entry)
        except Exception as e:
            logger.warning(
                f"Cppcheck analysis failed for repository %s.",
                repo_path.split("/")[-1]
            )
            logger.debug(e, exc_info=True)

    @staticmethod
    def _relative_file_paths(res: DataFrame, repo_path: str) -> DataFrame:
        """
        Replace absolute file paths by paths relative to the repository.
        This ensures that the same file can be identified in the downstream
        and in the upstream repository.

        Args:
            res: DataFrame with analysis results for a repository.
            repo_path: Path to the analysed repository.

        Returns:
            The results with file paths relative to the repository.
        """
        repo_prefix = path.join(repo_path, "")
        res["file_path"] = res["file_path"].apply(
            lambda x: x.removeprefix(repo_prefix)
        )
        return res

    @staticmethod
    def _repo_file_paths(
            lizard_paths: dict[str, str],
            repo_paths: dict[str, str],
            window: int
    ) -> dict[str, set[str] | None]:
        """
        Determine which files each repository contains in a snapshot.

        Lizard file metrics list every file of a repository, whereas the
        cppcheck report only lists files with issues. The full file set is
        therefore always derived from the lizard results, to correctly
        consider fixed issues.

        Args:
            lizard_paths: Paths to the lizard results per repository.
            repo_paths: Paths to the analysed repositories.
            window: Temporal snapshot identifier.

        Returns:
            The dictionary of relative file paths in each repository, or None
            for a repository without lizard results.
        """
        file_paths = {}
        for repo_type, lizard_path in lizard_paths.items():
            files = safe_read_csv(path.join(
                lizard_path, f"file_metrics_{repo_type}_{window}.csv"
            ))
            if files is None:
                file_paths[repo_type] = None
                continue

            files = CodeAnalyser._relative_file_paths(
                files, repo_paths[repo_type]
            )
            file_paths[repo_type] = set(files["file_path"])

        return file_paths

    @staticmethod
    def _unify_metrics(
            res_paths: dict[str, str],
            lizard_paths: dict[str, str],
            repo_paths: dict[str, str],
            package_path: str,
            windows: list[int],
            tool: str,
            downstream_path: str | None = None
    ) -> None:
        """
        Unify code metrics across upstream and downstream repository to remove
        duplicates and calculate metrics correctly.

        A file present in both repositories is measured once, preferably by
        the most downstream repository, as that is the shipped version.
        The upstream repository only contributes files which are
        missing downstream, e.g. if the downstream repository merely holds the
        packaging.

        Args:
            res_paths: Paths to the individual results per repository.
            lizard_paths: Paths to the lizard results per repository, which
                determine the file ownership.
            repo_paths: Paths to the analysed repositories.
            package_path: Path to store the unified results of the package.
            windows: Temporal snapshot identifiers to unify.
            tool: Code analysis tool (e.g. lizard or cppcheck).
            downstream_path: Package directory in a mono repository, or None.
        """
        if tool == "lizard":
            metrics_prefix = ["file_metrics", "function_metrics"]
        elif tool == "cppcheck":
            metrics_prefix = ["report"]
        else:
            return

        # End package directory string with a trailing slash to ensure that
        # other packages with longer names are not matched.
        dir_prefix = downstream_path.strip("/").removeprefix("./").strip("/") \
            + "/" if downstream_path else None

        # If a file is contained in both downstream and upstream repositories,
        # we prefer the downstream repository, as it ships the version reaching
        # users, including the patches applied to it.
        repo_precedence = ["down", "up"]

        # Unify and store results per analysis window.
        for w in windows:
            repo_files = CodeAnalyser._repo_file_paths(
                lizard_paths, repo_paths, w
            )
            if dir_prefix and repo_files.get("down") is not None:
                # Select only files from the package directory in mono
                # repositories.
                repo_files["down"] = {
                    f for f in repo_files["down"] if f.startswith(dir_prefix)
                }

            for prefix in metrics_prefix:
                # Collect the results of all repositories of the package.
                results = {}
                for repo_type in repo_precedence:
                    res_path = res_paths.get(repo_type)
                    if res_path is None:
                        continue

                    res = safe_read_csv(
                        path.join(res_path, f"{prefix}_{repo_type}_{w}.csv")
                    )
                    if res is None:
                        continue

                    res = CodeAnalyser._relative_file_paths(
                        res, repo_paths[repo_type]
                    )
                    if dir_prefix and repo_type == "down":
                        # Limit the downstream repository to the package
                        # directory in mono repositories.
                        res = res[res["file_path"].str.startswith(dir_prefix)]
                    results[repo_type] = res

                if not results:
                    # No metrics were captured for this window, so we can skip.
                    continue

                # Without a file list, a file shared by the repositories would
                # be measured twice. Reporting no metrics is preferred over
                # reporting wrong ones.
                missing = [
                    r for r in results if repo_files.get(r) is None
                ]
                if len(results) > 1 and missing:
                    logger.warning(
                        "No lizard file list for the %s repository in window "
                        "%s. Skipping the unified %s results.",
                        ", ".join(missing), w, tool
                    )
                    continue

                # Determine which repository owns a file and counts for metrics
                # calculation. The downstream repository is preferred, as it
                # ships the package.
                metrics = []
                own = set()
                for repo_type, res in results.items():
                    # Skip files already measured in a downstream repository.
                    metrics.append(res[~res["file_path"].isin(own)])
                    # Assign remaining files to the current repository.
                    own |= repo_files.get(repo_type) or set()

                # Remove duplicate metrics for the same reference, in case a
                # tool reported it repeatedly for the same repository.
                metrics = concat(metrics)
                metrics.drop_duplicates(inplace=True)

                # Store in the unified package path, which collects results
                # from both repositories belonging to the same package.
                makedirs(package_path, exist_ok=True)
                metrics.to_csv(
                    path.join(package_path, f"{prefix}_{w}.csv"), index=False
                )

    @staticmethod
    def _get_cwe_mapping(cwe_ids: list, cwe_db_path: str) -> dict:
        """
        Retrieve the official recommendations on CWE usage for automated
        vulnerability detection from the CWE database.

        Args:
            cwe_ids: List of unique CWE IDs to query.
            cwe_db_path: Path to the CWE database file.

        Returns:
            Vulnerability mapping for all CVEs.
        """
        cwe_dict = {}

        try:
            # Clean identified CWE IDs to ensure that the API call will refer
            # to the right ID.
            cwe_ids = [int(x) for x in cwe_ids if not math.isnan(x)]
            cwe_ids_str = ",".join(map(str, cwe_ids))

            # Build local CWE mapping database.
            data = get_api_data(
                f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_ids_str}"
            )
            for cwe in data:
                cwe_id = cwe.get("ID")
                cwe_type = cwe.get("Type")
                if cwe_type.endswith("_weakness"):
                    cwe_type = "weakness"
                cwe_url = f"https://cwe-api.mitre.org/api/v1/cwe/{cwe_type}/" \
                          f"{cwe_id}"
                cwe_data = get_api_data(cwe_url)
                usage = next(
                    iter(cwe_data.values())
                )[0].get("MappingNotes").get("Usage")
                cwe_dict[cwe_id] = usage

            # Store local CWE mapping database for debugging.
            cwe_mapping = DataFrame(
                list(cwe_dict.items()),
                columns=["cwe", "mapping"]
            )
            cwe_mapping.to_csv(cwe_db_path, index=False)
        except Exception as e:
            logger.warning("Error during CWE vulnerability mapping query.")
            logger.debug(e, exc_info=True)

        return cwe_dict

    def _add_vulnerability_mapping_notes(self, analysis_path: str):
        """
        Annotate cppcheck reports with the official CWE vulnerability
        mapping indicating whether the CWE is suitable for automated
        vulnerability detection.

        Args:
            analysis_path: Path to the cppcheck analysis results.
        """
        # Get all identified CWEs to limit the number of API requests.
        cwe_ids = []
        for repo_dir in listdir(analysis_path):
            repo_analysis_path = path.join(analysis_path, repo_dir)
            if not path.isdir(repo_analysis_path):
                continue
            for report_file in listdir(repo_analysis_path):
                if report_file.endswith(".csv"):
                    csv_report_path = path.join(
                        repo_analysis_path, report_file
                    )
                    report_table = read_csv(csv_report_path, encoding="utf-8")
                    report_cwe_ids = report_table["cwe"].unique().tolist()
                    for cwe in report_cwe_ids:
                        if cwe not in cwe_ids:
                            cwe_ids.append(cwe)

        # Get official vulnerability mapping notes from the CWE REST API.
        cwe_db_path = path.join(analysis_path, "cwe_mapping.csv")
        cwe_dict = self._get_cwe_mapping(cwe_ids, cwe_db_path)

        # Annotate each cppcheck report with the vulnerability mapping notes.
        for repo_dir in listdir(analysis_path):
            repo_analysis_path = path.join(analysis_path, repo_dir)
            if not path.isdir(repo_analysis_path):
                continue
            for report_file in listdir(repo_analysis_path):
                if report_file.endswith(".csv"):
                    csv_report_path = path.join(
                        repo_analysis_path, report_file
                    )
                    report_table = read_csv(csv_report_path, encoding="utf-8")
                    report_table["mapping"] = report_table["cwe"].map(
                        lambda x: "" if math.isnan(x) else
                        cwe_dict[str(int(x))]
                    )
                    report_table["cwe"] = report_table["cwe"].astype("Int64")
                    report_table.to_csv(
                        csv_report_path,
                        encoding="utf-8",
                        index=False
                    )

    def analyse(
            self,
            packages: dict[str, PackageInfo],
            repo_dir: str,
            analysis_dir: str,
            history_months: int,
            window_months: int,
            shift_months: int = 0,
            jobs: int = 1,
            lizard_analysis=False,
            cppcheck_analysis = False
    ) -> None:
        """
        Analyse code metrics for each repository.

        Args:
            packages: Dictionary of package identifiers and their metadata.
            repo_dir: Directory where the git repositories are cloned.
            analysis_dir: Directory where the analysis results will be stored.
            history_months: Maximum number of months to look back.
            window_months: Time interval in months for rate calculations.
            shift_months: Number of months between the start of two
                consecutive windows.
            jobs: Number of repositories to analyse in parallel.
            lizard_analysis: Whether to lizard analysis is required.
            cppcheck_analysis: Whether to cppcheck analysis is required.
        """
        if cppcheck_analysis:
            # Check whether cppcheck is installed and available in the PATH.
            exec_path = shutil.which("cppcheck")
            if exec_path is None:
                logger.warning(
                    "Cppcheck is not installed or not available in PATH. "
                    "Skipping analysis."
                )
                cppcheck_analysis = False

        # Determine the time windows to analyse snapshots for. Windows may
        # overlap to obtain more snapshots of a repository.
        windows = analysis_windows(history_months, window_months, shift_months)

        # Plan the analysis of each repository in a separate worker.
        repo_snapshots = {}
        package_dirs = {}
        planned = set()
        monorepos = monorepo_downstreams(packages)

        for package_id, package_info in packages.items():
            urls = {
                "down": package_info.downstream_repo,
                "up":   package_info.upstream_repo
            }
            checkouts = {
                "down": package_info.downstream_checkout,
                "up":   package_info.upstream_checkout
            }

            package_name = package_info.name
            repo_paths = {}
            lizard_paths = {}
            cppcheck_paths = {}

            for repo_type, repo_url in urls.items():
                if repo_url is None or checkouts[repo_type] is None:
                    continue

                logger.debug(
                    "Processing %s repository for package %s...",
                    repo_type,
                    package_name
                )

                # Get the cloned repository.
                repo_name = repo_dir_name(repo_url, repo_type)
                if repo_name is None:
                    continue

                repo_path = path.join(repo_dir, repo_name)
                if not path.isdir(path.join(repo_path, ".git")):
                    logger.warning(
                        f"Could not find repository %s for code analysis.",
                        repo_name
                    )
                    continue

                # Store the results per repository and version. Packages
                # sharing them are only analysed once for performance.
                res_name = analysis_dir_name(repo_name, checkouts[repo_type])
                repo_paths[repo_type] = repo_path
                lizard_paths[repo_type] = path.join(
                    analysis_dir, "lizard", "repos", res_name
                )
                cppcheck_paths[repo_type] = path.join(
                    analysis_dir, "cppcheck", "repos", res_name
                )

                if res_name in planned:
                    continue

                planned.add(res_name)
                repo_snapshots.setdefault(repo_path, []).append(
                    (repo_type, checkouts[repo_type], res_name)
                )

            downstream_path = package_info.downstream_path
            if package_info.downstream_repo in monorepos \
                    and downstream_path is None and "down" in repo_paths:
                # In mono repositories, a package without a known directory,
                # would get the enitre repository's metrics.
                # Reporting no downstream code is more accurate.
                logger.warning(
                    "No package directory known for %s in the mono repository "
                    "%s. Downstream code is not attributed to the package.",
                    package_name, package_info.downstream_repo
                )
                for paths in (repo_paths, lizard_paths, cppcheck_paths):
                    paths.pop("down", None)

            package_dirs[package_id] = (
                package_name,
                repo_paths,
                lizard_paths,
                cppcheck_paths,
                downstream_path
            )

        # Analyse the repositories, one worker per repository.
        if jobs == 1:
            # Analyse all repositories sequentially in one process.
            for n, (repo_path, snapshots) in enumerate(
                    repo_snapshots.items(), start=1
            ):
                try:
                    self._analyse_repo(
                        repo_path,
                        snapshots,
                        analysis_dir,
                        windows,
                        lizard_analysis,
                        cppcheck_analysis
                    )
                except Exception as e:
                    self._clean_results(analysis_dir, snapshots, e)

                logger.info(
                    "Code analysis performed for %s of %s repositories.",
                    n, len(repo_snapshots)
                )
        else:
            # Parallelise repository analysis.
            with ProcessPoolExecutor(
                    max_workers=jobs if jobs > 0 else None,
                    initializer=_setup_worker_logging,
                    initargs=(logger.getEffectiveLevel(),)
            ) as pool:
                analyses = {
                    pool.submit(
                        self._analyse_repo,
                        repo_path,
                        snapshots,
                        analysis_dir,
                        windows,
                        lizard_analysis,
                        cppcheck_analysis
                    ): snapshots
                    for repo_path, snapshots in repo_snapshots.items()
                }

                for n, analysis in enumerate(as_completed(analyses), start=1):
                    snapshots = analyses[analysis]
                    try:
                        analysis.result()
                    except Exception as e:
                        self._clean_results(analysis_dir, snapshots, e)

                    logger.info(
                        "Code analysis performed for %s of %s repositories.",
                        n, len(analyses)
                    )

        # Unify the results across repositories and snapshots to remove
        # duplicate references (e.g. to the same files) to only count them
        # once when aggregating metrics.
        for package_name, repo_paths, lizard_paths, cppcheck_paths, \
                downstream_path in package_dirs.values():
            if lizard_analysis:
                self._unify_metrics(
                    lizard_paths,
                    lizard_paths,
                    repo_paths,
                    path.join(analysis_dir, "lizard", package_name),
                    list(windows.keys()),
                    "lizard",
                    downstream_path=downstream_path
                )
            if cppcheck_analysis:
                self._unify_metrics(
                    cppcheck_paths,
                    lizard_paths,
                    repo_paths,
                    path.join(analysis_dir, "cppcheck", package_name),
                    list(windows.keys()),
                    "cppcheck",
                    downstream_path=downstream_path
                )

        if cppcheck_analysis:
            # Annotate cppcheck reports with CWE vulnerability mapping notes.
            self._add_vulnerability_mapping_notes(
                path.join(analysis_dir, "cppcheck")
            )