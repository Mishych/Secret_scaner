import os
import re
from colored import fg, attr
import aiohttp
import argparse
import asyncio
import aiofiles
from validators import SecretValidator as sv


async def get_commits(repo, token, verbose=False):
    """Gets commits from a GitHub repository using GitHub API asynchronously"""
    url = f"https://api.github.com/repos/{repo}/commits"
    headers = {
        'Authorization': f'token {token}'
    } if token else {}
    if verbose:
        print(f"Fetching commits from {repo}...")

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as response:
            if response.status == 200:
                if verbose:
                    print(f"Successfully fetched commits.")
                commits_list = []
                commits = await response.json()
                for commit in commits:
                    commits_list.append(commit['commit']['message'])
                return commits_list
            else:
                print(f"Error fetching commits: {response.status}")
                return None
    
AWS_SECRET_REGEX = r"(?i)(AKIA[0-9A-Z]{16}):([A-Za-z0-9/+=]{40})"
aws_secret = ":"
       
async def try_login(secret, type_secret):
    global aws_secret
    
    if type_secret == "aws":
        access_key, secret_key = secret.split(":")
        return sv.validate_aws_keys(access_key, secret_key)
    elif type_secret == "AWS Access Key ID":
        aws_secret = secret + aws_secret
        if re.search(AWS_SECRET_REGEX, aws_secret):
            tr_log = await try_login(aws_secret, "aws")
            aws_secret = ":"
            return tr_log
        return ""  
    elif type_secret == "AWS Secret Access Keys":
        aws_secret = aws_secret + secret
        if re.search(AWS_SECRET_REGEX, aws_secret):
            tr_log = await try_login(aws_secret, "aws")
            aws_secret = ":"
            return tr_log
        return ""
    elif type_secret == "github":
        return sv.validate_github_token(secret)
    elif type_secret == "Google API Key":
        return sv.validate_google_api_key(secret)
    elif type_secret == "URI-secret":
        return sv.validate_uri_with_credentials(secret)
    elif type_secret == "slack":
        return sv.validate_slack_token(secret)
    else:
        return type_secret
            
async def valid_secret(secret):
    """
    Function to check the secret
    """
    clean_secret = re.sub(r"-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----", "", secret)
    pattern = rf"(.)\1{{{4-1},}}"
    if bool(re.search(pattern, clean_secret.upper())):
        return False
    test_patterns = ["EXAMPLE", "TEST", "FAKE", "DUMMY", "12345",
                     "ABCDF", "A1B2C3D4" "FAKEKEY", "SECRET", "SAMPLE", "ACCESS"]
    for pattern in test_patterns:
        if pattern in secret.upper():
            return False
    return True
    
async def find_commit_secrets(t_regexp, commits, verbose=False):
    """Search secrets in commit messages"""
    output = ""
    try:
        for commit in commits:
            highlighted_line = commit
            for regexp, type_secret in t_regexp:
                matches = re.findall(regexp, commit)
                if matches:
                    for match in matches:
                        if await valid_secret(match):
                            if verbose:
                                print(f"Secrets found in {commit}")
                                verbose=False
                            try_log = await try_login(match, type_secret.strip())
                            highlighted_match = f"{fg('light_green')}{match}{attr(0)}"
                            highlighted_line = highlighted_line.replace(match, highlighted_match) 
                            output += f"\nSecrets found in commit: {commit}\n"
                            output += highlighted_line + " " + try_log + "\n" 
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
    parser.add_argument("-t", "--token", help="GitHub token for authentication")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

async def main():
    """Main function"""
    args = parse_arguments()
    regexp_to_search = "regex_patterns/regex_secrets.csv"
    if os.path.exists(regexp_to_search):
        async with aiofiles.open(regexp_to_search, "r", encoding="UTF-8") as file_regs:
            regs_and_type = await file_regs.readlines()
            regs = [reg.rsplit(', ', 1)[0] for reg in regs_and_type]
            type_regs = [type_reg.rsplit(', ', 1)[1] for type_reg in regs_and_type]
            regexp = [re.compile(regexp.strip(), re.IGNORECASE) for regexp in regs]
            regexp_type = list(zip(regexp, type_regs))
    else:
        print(f"{fg('yellow')}[-] File {regexp_to_search} is missing.{attr(0)}")
        exit(1)
        
    token = args.token if args.token else None       
    output = []
    commits = await get_commits(args.repo, token, args.verbose)

    if commits:
        result = await find_commit_secrets(regexp_type, commits)
        if result:
            output.append(result)
    if output:
        print("\n".join(output))
    else:
        print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
    
    
if __name__ == "__main__":
    asyncio.run(main())