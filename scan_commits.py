import os
import re
from colored import fg, attr
import requests
import argparse


# Gets commits from a GitHub repository using GitHub API
def get_commits(owner, repo, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    
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
    match_count = {}
    try:
        for regexp in t_regexp:
            for commit in commits:
                matches = re.findall(regexp, commit)
                if matches:
                    for match in matches:
                        match_key = match[1]

                        if match_key in match_count:
                            match_count[match_key] += 1
                        else:
                            match_count[match_key] = 1

                        if match_count[match_key] > 3:
                            continue
                        
                        output += f"\n>>> Found secrets in commit\n"
                        output += f"{fg('white')}{match[0].lstrip()}{attr(0)}" + \
                                    f"{fg('light_green')}{match[1]}{attr(0)}" + \
                                    f"{fg('white')}{match[-1].rstrip()}{attr(0)}\n"
        
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
    parser.add_argument("-o", "--owner", required=True, help="Repository owner")
    parser.add_argument("-r", "--repo", required=True, help="Repository name")
    parser.add_argument("-re", "--regex", nargs="+", default=None, help="One or more regular expressions to search for secrets (optional)")
    
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()
      
    if args.regex:
        t_regexp = [re.compile(r'(.{0,100})(' + reg + ')(.{0,100})', re.IGNORECASE) for reg in args.regex]
        
    else:
        regexp_to_search = "regex_patterns/regex_secrets.csv" 
        if os.path.exists(regexp_to_search):
            with open(regexp_to_search, "r", encoding="UTF-8") as file_regs:
                regs = file_regs.readlines()
                t_regexp = [reg.strip() for reg in regs if reg.strip()]
                t_regexp = [re.compile(r'(.{0,100})(' + regexp + ')(.{0,100})', re.IGNORECASE) for regexp in t_regexp]
        else:
            print(f"{fg('yellow')}[-] Search term is missing.{attr(0)}")
            exit(1)
            
    commits_list = []
    
    commits = get_commits(args.owner, args.repo, args.token)

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
