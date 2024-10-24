# GitHub Secret Finder

This is a Python script that helps you find potential secrets in a GitHub repository by searching through both **file contents** and **commit messages** using regular expressions. It can search both local files and files in a GitHub repository, retrieve their contents, and identify secrets based on regex patterns.


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
python detect_secrets.py -r <REPO_PATH> [-p <FILE_PATH>] [-re <REGEX_PATTERN>] [--verbose]
```

An example of running a file `detect_secrets.py`

```bash
python detect_secrets.py -r name/repo -p python_file.py -re '(AKIA|ASIA)[A-Z0-9]{16,}' 'AWS[A-Z0-9]{16,40}' --verbose
```

The detect_secrets_entropy.py script combines entropy analysis with regular expressions to identify potential secrets. You can run `detect_secrets_entropy.py` with the same arguments as used for `detect_secrets.py`.

For example of running a file `detect_secrets_entropy.py`:

```bash
python detect_secrets_entropy.py -r name/repo -p python_file.py -re '(AKIA|ASIA)[A-Z0-9]{16,}' 'AWS[A-Z0-9]{16,40}' --verbose
```

In addition to searching file contents, the script can now also search for secrets in commit messages. Only the repository path `(-r <REPO_PATH>)` is required, while the other arguments are optional. To use this feature, run the following command:

```bash
python search_commits.py -r <REPO_PATH> [-re <REGEX_PATTERN>] [--verbose]
```

For example of running a file `search_commits.py`:

```bash
python search_commits.py -r name/repo -re '(AKIA|ASIA)[A-Z0-9]{16,}' 'AWS[A-Z0-9]{16,40}' --verbose
```