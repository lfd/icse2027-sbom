import logging
import math
import re
import requests

from bs4 import BeautifulSoup
from git import Repo, GitCommandError
from hashlib import sha256
from os import path, remove
from pandas import DataFrame, read_csv, to_datetime
from pandas.errors import ParserError
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Some hosts reject requests which do not identify their client. crates.io,
# for instance, answers 403 without a user agent.
API_USER_AGENT = "sbom-analysis"

# Matches "test" files or directory names, i.e. at the beginning or preceded
# by a separator such as "_".
# Important: We deliberately avoid substring matching due to false positives,
# for instance "latest" or "contest".
TEST_PATH_PATTERNS = re.compile(r"(?:^|[^a-zA-Z0-9])test", re.IGNORECASE)


def checkout_version(repo: Repo, revision: str) -> None:
    """
    Helper function to check out a revision of a repository.

    An interrupted run can leave the index lock of a repository behind, which
    causes every later checkout to fail. In this case, we delete the lock.

    Args:
        repo: Repository to check out.
        revision: Branch, tag or commit to check out.
    """
    try:
        repo.git.checkout(revision, force=True)
        return
    except GitCommandError as e:
        lock_path = path.join(repo.git_dir, "index.lock")
        if "index.lock" not in str(e) or not path.exists(lock_path):
            raise

        logger.warning(
            "Removing index lock of repository %s.",
            repo.working_dir
        )
        remove(lock_path)

    repo.git.checkout(revision, force=True)


def repo_dir_name(repo_url: str, repo_type: str) -> str | None:
    """
    Helper function to derive the directory name of a repository from its URL.

    Multiple packages can be managed in the same repository. This function
    ensures deduplication while accounting for potential name collisions, e.g.
    in downstream and upstream repositories.

    Args:
        repo_url: Remote repository URL.
        repo_type: Type of repository (down or up).

    Returns:
        The directory name of the repository, or None if the repository name
        could not be derived.
    """
    # Derive directory name segments from the repository URL.
    try:
        url = urlparse(
            repo_url if "://" in repo_url else "https://" + repo_url
        )
        segments = [s for s in url.path.split("/") if s]
    except (TypeError, ValueError):
        url = segments = None

    if url is None or not url.hostname or not segments:
        logger.warning(
            "Could not parse repository URL from %s. Ignoring.",
            repo_url
        )
        return None

    # Host labels which do not identify the source of a repository, i.e. common
    # top-level domains and prefixes shared by many repository hosts.
    generic_url_labels = {
        "www", "git", "com", "org", "net", "io", "dev", "eu", "de", "uk"
    }

    # Keep the distinctive part of the host as source, e.g. salsa.
    labels = [
        l for l in url.hostname.split(".") if l not in generic_url_labels
    ]
    segments[-1] = segments[-1].removesuffix(".git")
    name = "_".join(labels + segments).lower()

    # Replace unsafe characters and limit directory name length.
    name = re.sub(r"[^a-z0-9_-]", "_", name)[:80]

    return f"{name}_{repo_type}"


def analysis_dir_name(repo_name: str, checkout: str) -> str:
    """
    Helper function to derive the directory name for the code analysis results
    of a repository.

    Code analysis inspects a snapshot of the repository files, so its results
    depend on the repository and the version checked out. Packages sharing
    both are therefore analysed only once.

    Replacing unsafe characters in repository names maps different references
    to the same name, e.g. "v1.2.3" and "V1_2_3". To prevent collisions, a
    short digest of the checkout string is appended to the directory name.

    Args:
        repo_name: Directory name of the repository.
        checkout: Branch, tag or commit analysed in the repository.

    Returns:
        The directory name of the analysis results.
    """
    digest = sha256(checkout.encode("utf-8")).hexdigest()[:4]
    checkout = re.sub(r"[^a-z0-9_-]", "_", checkout.lower())
    return f"{repo_name}_{checkout}_{digest}"


def analysis_windows(
        history_months: int,
        window_months: int,
        shift_months: int
) -> dict[int, int]:
    """
    Helper function to determine the time windows to analyse. Windows are
    window_months long and shifted by shift_months.

    Important: The configuration must stay consistent across analysis phases,
    as the window identifier is part of the file names of the results.

    Args:
        history_months: Maximum number of months to look back.
        window_months: Time interval length in months.
        shift_months: Number of months between the start of two consecutive
            windows. Values <1 yield windows which do not overlap.

    Returns:
        Dictionary of window identifiers and their offset in months relative to
        the reference date. The most recent window has the highest identifier.
    """
    shift_months = shift_months if shift_months > 0 else window_months

    n_window = math.floor(
        (history_months - window_months) / shift_months
    ) + 1

    if n_window < 1:
        logger.warning(
            "History of %s months is shorter than the window length of %s "
            "months. No time window can be analysed.",
            history_months, window_months
        )
        return dict()

    return {
        (n_window - n): n * shift_months for n in range(int(n_window))
    }


def window_lag(window_months: int, shift_months: int) -> int:
    """
    Helper function to determine how many windows lie between a window and the
    preceding window it is compared to.

    So far, this is only needed for the trends based on code analysis
    snapshots, as commit-based trends slice the commit table by date. If the
    window length is not a multiple of the shift, we compare to the closest
    preceding window, as the code likely stayed consistent in between.

    Args:
        window_months: Time interval length in months.
        shift_months: Number of months between the start of two consecutive
            windows. Values <1 yield windows which do not overlap.

    Returns:
        The number of windows corresponding to one window length.
    """
    shift_months = shift_months if shift_months > 0 else window_months
    return max(1, round(window_months / shift_months))


def safe_read_csv(file_path: str) -> DataFrame | None:
    """
    Helper function to safely read a CSV table, returning None if the file
    does not exist.

    Args:
        file_path: Path to the CSV file.

    Returns:
        The CSV table as DataFrame if the file exists, None otherwise.
    """
    try:
        return read_csv(file_path)
    except FileNotFoundError:
        logger.debug(f"File %s not found.", file_path)
        return None
    except (ParserError, ValueError):
        # An interrupted run can leave an incomplete table behind, which is
        # reported for post-run fixes.
        logger.warning(
            "Could not read table %s. Ignoring.",
            file_path,
            exc_info=True
        )
        return None


def safe_read_commits(commit_path: str) -> DataFrame | None:
    """
    Helper function to safely read the commit history of a repository, returning
    an empty DataFrame if the file does not exist.

    Args:
        commit_path: Path to the commit table.

    Returns:
        The commit table as a DataFrame if the file exists, None otherwise.
    """
    try:
        commits = read_csv(commit_path)
        commits["author_date"] = to_datetime(commits["author_date"],
                                 utc=True,
                                 format="%a %b %d %H:%M:%S %Y %z")
        commits["committer_date"] = to_datetime(commits["committer_date"],
                                                utc=True,
                                                format="%a %b %d %H:%M:%S %Y %z")
        commits = commits.sort_values(by="committer_date", ascending=True)
        return commits
    except FileNotFoundError:
        logger.debug(f"File %s not found.", commit_path)
        return None
    except (ParserError, ValueError, KeyError):
        # An interrupted run can leave an incomplete table behind, which is
        # reported for post-run fixes.
        logger.warning(
            "Could not read the commit history in %s. Ignoring.",
            commit_path,
            exc_info=True
        )
        return None


def post_api_data(url: str, data: dict) -> dict | None:
    """
    Helper function to post JSON data to a REST API endpoint.

    Args:
        url: The URL of the REST API endpoint.
        data: The JSON data to post as a dictionary.

    Returns:
        The JSON response data as a dictionary if the request is successful,
        None otherwise.
    """
    logger.debug("Posting JSON data %s to %s", data, url)
    response = requests.post(url, json=data)
    response.raise_for_status()
    return response.json()


def get_api_data(url: str) -> dict | None:
    """
    Helper function to fetch JSON data from a REST API endpoint.

    Args:
        url: The URL of the REST API endpoint.

    Returns:
        The JSON data as a dictionary if the request is successful, None
        otherwise.
    """
    response = requests.get(url, headers={"User-Agent": API_USER_AGENT})
    response.raise_for_status()
    return response.json()


def get_file_data(url: str) -> bytes | None:
    """
    Helper function to fetch a file as raw bytes.

    Args:
        url: The URL of the file.

    Returns:
        The file content if the request is successful, None otherwise.
    """
    logger.debug("Downloading %s", url)
    response = requests.get(url, headers={"User-Agent": API_USER_AGENT})
    response.raise_for_status()
    return response.content


def test_url(url: str) -> bool:
    """
    Helper function to test if a URL is reachable.

    Args:
        url: The URL to test.

    Returns:
        True if the URL is reachable, False otherwise.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        r = requests.head(
            url,
            allow_redirects=True,
            timeout=3,
            headers=headers
        )
        if r.status_code != 200:
            return False

        # Handle sign-in pages, which could be misinterpreted as a reachable
        # repository.
        # Pages a host redirects to instead of answering that a repository does
        # not exist (e.g. sign-in pages returned with status 200).
        sign_in_paths = ("/users/sign_in", "/login", "/signin", "/session/new")
        if any(p in urlparse(r.url).path for p in sign_in_paths):
            logger.debug(
                "URL %s redirects to the sign-in page %s. Ignoring.",
                url, r.url
            )
            return False

        return True
    except Exception as e:
        logger.debug(e, exc_info=True)
        return False

def get_soup(url: str) -> BeautifulSoup | None:
    """
    Helper function to scrape a website and return its content with
    BeautifulSoup.

    Args:
        url: The URL to look up.

    Returns:
        The HTML content of the website if reachable, None otherwise.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        logger.debug(e)
        return None