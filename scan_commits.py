import os
import re
from colored import fg, attr
import requests
import argparse


# Gets commits from a GitHub repository using GitHub API
def get_commits(repo, token):
    url = f"https://api.github.com/repos/{repo}/commits"
    headers = {
        'Authorization': f'token {token}'
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching commits: {response.status_code}")
        return None
    

# Search secrets in commit messages
def find_commit_secrets(t_regexp, commits):
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
                output += f"\n>>> Found secrets in commit\n"
                output += highlighted_line
        
        if not output:
            print(f"[+] No secrets found in commits")

    except Exception as e:
        error_message = f"[-] Error occurred while reading : {e}"
        print(f"{fg('red')}{error_message}{attr(0)}")

    return output

parser = argparse.ArgumentParser()


# Function for processing command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--token", required=True, help="GitHub token for authentication")
    parser.add_argument("-r", "--repo", required=True, help="Repository path")
    parser.add_argument("-re", "--regex", nargs="+", default=None, help="One or more regular expressions to search for secrets (optional)")
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()
      
    if args.regex:
        t_regexp = [re.compile(reg, re.IGNORECASE) for reg in args.regex]
        
    else:
        regexp_to_search = "regex_secrets.csv" 
        if os.path.exists(regexp_to_search):
            with open(regexp_to_search, "r", encoding="UTF-8") as file_regs:
                regs = file_regs.readlines()
                t_regexp = [reg.strip() for reg in regs if reg.strip()]
                t_regexp = [re.compile(regexp, re.IGNORECASE) for regexp in t_regexp]
        else:
            print(f"{fg('yellow')}[-] Search term is missing.{attr(0)}")
            exit(1)
            
    commits_list = []
    commits = get_commits(args.repo, args.token)

    if commits:
        for commit in commits:
            commits_list.append(commit['commit']['message'])
            
    output = []
    results = find_commit_secrets(t_regexp, commits_list)
    if results:
        output.append(results)

    if output:
        print("\n".join(output))
    else:
        print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
    

if __name__ == "__main__":
    main()
