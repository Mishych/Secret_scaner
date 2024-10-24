import os
import re
from colored import fg, attr
import requests
import argparse


def get_commits(repo, verbose=False):
    """Gets commits from a GitHub repository using GitHub API"""
    url = f"https://api.github.com/repos/{repo}/commits"
    
    if verbose:
        print(f"Fetching commits from {repo}...")

    response = requests.get(url)
    
    if response.status_code == 200:
        if verbose:
            print(f"Successfully fetched commits.")
            
        commits_list = []
        commits = response.json()
        
        for commit in commits:
            commits_list.append(commit['commit']['message'])
        return commits_list
    
    else:
        print(f"Error fetching commits: {response.status_code}")
        return None
    
def find_commit_secrets(t_regexp, commits):
    """Search secrets in commit messages"""
    output = ""
    
    try:
        for commit in commits:
            highlighted_line = commit
            found_match = False
            for regexp in t_regexp:
                matches = re.findall(regexp, commit)
                
                if matches:
                    found_match = True
                    for match in matches:
                        highlighted_match = f"{fg('light_green')}{match}{attr(0)}"
                        highlighted_line = highlighted_line.replace(match, highlighted_match)
            if found_match:
                output += f"\nSecrets found in commit: {commit}\n"
                output += highlighted_line + "\n"
        
        if not output:
            print(f"[+] No secrets found in commits")

    except Exception as e:
        error_message = f"[-] Error occurred while reading: {e}"
        print(f"{fg('red')}{error_message}{attr(0)}")

    return output

def parse_arguments():
    """Function for processing command-line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repo", required=True, help="Repository path")
    parser.add_argument("-re", "--regex", nargs="+", default=None, help="One or more regular expressions to search for secrets (optional)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
      
    if args.verbose:
        print("Verbose mode enabled.")
      
    if args.regex:
        t_regexp = [re.compile(reg, re.IGNORECASE) for reg in args.regex]
        
    else:
        regexp_to_search = "regex_patterns/regex_secrets.csv" 
        if os.path.exists(regexp_to_search):
            if args.verbose:
                print(f"Loading regex patterns from {regexp_to_search}...")
            with open(regexp_to_search, "r", encoding="UTF-8") as file_regs:
                regs = file_regs.readlines()
                t_regexp = [reg.strip() for reg in regs if reg.strip()]
                t_regexp = [re.compile(regexp, re.IGNORECASE) for regexp in t_regexp]
        else:
            print(f"{fg('yellow')}[-] Search term is missing.{attr(0)}")
            exit(1)
            
    commits = get_commits(args.repo, args.verbose)
            
    output = []
    results = find_commit_secrets(t_regexp, commits)
    if results:
        output.append(results)

    if output:
        print("\n".join(output))
    else:
        print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
    

if __name__ == "__main__":
    main()
