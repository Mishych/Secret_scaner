# GitHub Secret Finder

This is a Python script that helps you find potential secrets in a GitHub repository by searching through both **file contents** and **commit messages** using regular expressions and entropy. It can search both local files and files in a GitHub repository, retrieve their contents, and identify secrets based on regex patterns.


## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/Mishych/Secret_scaner.git
    cd Secret_scaner
    ```

2. Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run a script that scans files in the repository for secrets, use the following command. Only the repository path `(-r <REPO_PATH>)` is required, while the other arguments are optional:

```bash
python detect_secrets.py [-r <REPO_PATH>] [-t <GITHUB_TOKEN>] [-l <LOCAL_PATH>] [-p <FILE_PATH>] [--verbose]
```

- `-r <REPO_PATH>`: (Optional) Path to the GitHub repository.
- `-t <GITHUB_TOKEN>`: (Optional) GitHub token for authentication.
- `-p <FILE_PATH>`: (Optional) Specific file or directory to scan. If omitted, the entire repository will be scanned.
- `-l <LOCAL_PATH>`: (Optional) Path in the local repository to search.
- `--verbose`: (Optional) Enable detailed output.

Example of running a file when we want to scan a repository on GitHub `detect_secrets.py`

```bash
python detect_secrets.py -r name/repo -t ghp_........ -p python_file.py --verbose
```

To scan a local repository, provide the path using the `-l`, example of running a file `detect_secrets.py`

```bash
python detect_secrets.py -l /path/to/your/local/repository --verbose
```

The detect_secrets_entropy.py script combines entropy analysis with regular expressions to identify potential secrets. You can run `detect_secrets_entropy.py` with the same arguments as used for `detect_secrets.py`.

For example of running a file when we want to scan a repository on GitHub `detect_secrets_entropy.py`:

```bash
python detect_secrets_entropy.py -r name/repo -t ghp_........ -p python_file.py --verbose
```

To scan a local repository, example of running a file `detect_secrets_entropy.py`:

```bash
python detect_secrets_entropy.py -l /path/to/your/local/repository --verbose
```

In addition to searching file contents, the script can now also search for secrets in commit messages. Only the repository path `(-r <REPO_PATH>)` is required, while the other arguments are optional. To use this feature, run the following command:

```bash
python search_commits.py [-r <REPO_PATH>] [-t <GITHUB_TOKEN>] [--verbose]
```

For example of running a file `search_commits.py`:

```bash
python search_commits.py -r name/repo -t ghp_........ --verbose
```