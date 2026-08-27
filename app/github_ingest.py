import tempfile
import shutil
from git import Repo


def is_github_url(path: str) -> bool:
    """Check if the given path looks like a GitHub URL."""
    return path.startswith("https://github.com/") or path.startswith("git@github.com:")


def clone_repo(url: str) -> str:
    """Clone a GitHub repo into a temporary folder and return its path."""
    temp_dir = tempfile.mkdtemp(prefix="sentinel-")
    Repo.clone_from(url, temp_dir, depth=1)
    return temp_dir


def cleanup_repo(temp_dir: str) -> None:
    """Delete the temporary cloned folder."""
    shutil.rmtree(temp_dir, ignore_errors=True)


def extract_repo_name(url: str) -> str:
    """Extract a clean repo name from a GitHub URL."""
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name