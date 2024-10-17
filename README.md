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

To use the script, run the following command with the necessary arguments:

```bash
python script_name.py -t <GITHUB_TOKEN> -o <REPO_OWNER> -r <REPO_NAME> [-p <REPO_PATH>] [-re <REGEX_PATTERN>] [-f <FILE_PATTERNS>]
```

In addition to searching file contents, the script can now also search for secrets in commit messages. To use this feature, run the following command:

```bash
python search_commits.py -t <GITHUB_TOKEN> -o <REPO_OWNER> -r <REPO_NAME> [-re <REGEX_PATTERN>]
```
