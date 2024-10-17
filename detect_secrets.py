import os
import re
import json
from colored import fg, attr
import logging
import aiohttp
import asyncio
import argparse


# GitHub API URL
GITHUB_API_URL = "https://api.github.com/repos/{owner}/{repo}/contents/{path}"

logging.basicConfig(filename='scan_results.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', filemode='w')


# Function for retrieving the content of files from GitHub
async def get_file_content(token, owner, repo, path):
    headers = {"Authorization": f"token {token}"}
    url = GITHUB_API_URL.format(owner=owner, repo=repo, path=path)
    
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if data['type'] == 'file':
                    async with session.get(data['download_url']) as file_response:
                        if file_response.status == 200:
                            file_content = await file_response.text()
                            return file_content
                        else:
                            logging.error(f"[-] Failed to download file content: {file_response.status}")
                            return None
                else:
                    return None
            else:
                logging.error(f"[-] Failed to fetch file content: {response.status}")
                return None


# Searching for secrets in the file's text
async def find_secrets(t_regexp, content, path):
    output = ""
    match_count = {}
    try:
        lines = content.splitlines()
        for regexp in t_regexp:
            for line_number, line in enumerate(lines, start=1):
                matches = re.findall(regexp, line)
                if matches:
                    for match in matches:
                        match_key = match[1]

                        if match_key in match_count:
                            match_count[match_key] += 1
                        else:
                            match_count[match_key] = 1

                        if match_count[match_key] > 3:
                            continue
                        
                        output += f"\n>>> Found in {path} (line {line_number})\n"
                        output += f"{fg('white')}{match[0].lstrip()}{attr(0)}" + \
                                    f"{fg('light_green')}{match[1]}{attr(0)}" + \
                                    f"{fg('white')}{match[-1].rstrip()}{attr(0)}\n"
        
            if not output:
                logging.info(f"[+] No secrets found in {path}")

    except Exception as e:
        error_message = f"[-] Error occurred while reading {path}: {e}"
        logging.error(error_message)
        print(f"{fg('red')}{error_message}{attr(0)}")

    return output


# Searching for matching files in the local repository (for testing)
def find_files(directory, files_pattern):
    matches = []
    for root, _, files in os.walk(directory):
        for filename in files:
            for file_pattern in files_pattern:
                if re.search(file_pattern, filename):
                    matches.append(os.path.join(root, filename))
    return matches


# Searching for matching files in the GitHub repository
async def find_files_github(owner, repo, files_pattern, token, path):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as response:
            if response.status != 200:
                print(f"Failed to fetch contents from {url}: {response.status}")
                return []

            contents = await response.json()

            if isinstance(contents, dict) and contents['type'] == 'file':
                filename = contents['name']
                matches = []
                for file_pattern in files_pattern:
                    if re.search(file_pattern, filename):
                        matches.append(contents['path'])
                return matches
            
            elif isinstance(contents, list):
                matches = []
                tasks = []
                
                for content in contents:
                    if content['type'] == 'file':
                        filename = content['name']
                        for file_pattern in files_pattern:
                            if re.search(file_pattern, filename):
                                matches.append(content['path'])

                    elif content['type'] == 'dir':
                        tasks.append(find_files_github(owner, repo, files_pattern, token, content['path']))

                subdir_matches = await asyncio.gather(*tasks)
                for subdir_match in subdir_matches:
                    matches.extend(subdir_match)

                return matches
            else:
                print(f"Unexpected content structure from {url}")
                return []
 
            
# Saving the results to the found_secrets.json file
def save_results_to_file(results, file_path='found_secrets.json'):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logging.info(f"[+] Results saved to {file_path}")
    except Exception as e:
        logging.error(f"[-] Error while saving results to file: {e}")
        print(f"{fg('red')}[-] Error while saving results to file: {e}{attr(0)}")

parser = argparse.ArgumentParser()

# Function for processing command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="GitHub Secret Finder")
    parser.add_argument("-t", "--token", required=True, help="GitHub token for authentication")
    parser.add_argument("-o", "--owner", required=True, help="Repository owner")
    parser.add_argument("-r", "--repo", required=True, help="Repository name")
    parser.add_argument("-p", "--path", default="", help="Path in the repository to search (optional)")
    parser.add_argument("-re", "--regex", nargs="+", default=None, help="One or more regular expressions to search for secrets (optional)")
    parser.add_argument("-f", "--file", nargs="+", default=None, help="One or more files to search for secrets (optional)")
    
    return parser.parse_args()


# Main function
async def main():
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
          
    if args.file:
        regexp_file = args.file
    
    else:       
        search_file = "regex_patterns/file_paterns.csv"
        if os.path.exists(search_file):
            with open(search_file, "r", encoding="UTF-8") as f:
                reg_files = f.readlines()
                regexp_file = [reg_file.strip() for reg_file in reg_files if reg_file.strip()]
        else:
            print(f"{fg('yellow')}[-] Search term is missing.{attr(0)}")
            exit(1)
        
    found_files = await find_files_github(args.owner, args.repo, regexp_file, args.token, args.path)
    if not found_files:
        print(f"{fg('yellow')}[-] No files found.{attr(0)}")
        exit(1)
    
    output = []
    task = []
    
    for file in found_files:
        task.append(get_file_content(args.token, args.owner, args.repo, file))
    
    contents = await asyncio.gather(*task)
    
    for content, file in zip(contents, found_files):
        if content:    
            results = await find_secrets(t_regexp, content, file)
            if results:
                output.append(results)
            
    if output:
        print("\n".join(output))
        save_results_to_file(output)
    else:
        print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
  
        
if __name__ == "__main__":
    asyncio.run(main())
        
        
        
        
# search_terms = "regex_patterns/key_words.csv"
# if os.path.exists(search_terms):
    
#     with open(search_terms, "r", encoding="UTF-8") as f:
#         keys = f.readlines()
#         search_regexp = [re.compile(r'' + re.escape(term.strip()), re.IGNORECASE) for term in keys if term.strip()]
# else:
#     print(f"{fg('yellow')}[-] Search term is missing.{attr(0)}")
#     exit(1)
    
# directory_to_search = r"C:\Users\..."  
    
# found_files = find_files(directory_to_search, regexp_file) 
# found_files = ["scanning.py", ".env"]
    