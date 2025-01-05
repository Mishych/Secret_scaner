import os
import re
import json
from colored import fg, attr
import logging
import aiohttp
import asyncio
import aiofiles
import argparse
import math


logging.basicConfig(filename='scan_results.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', filemode='w')

async def get_file_content(repo, path, token, verbose=False):
    """Function for retrieving the content of files from GitHub"""
    headers = {"Authorization": f"token {token}"} if token else {}
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    if verbose:
        print(f"Fetching file content from: {path}")
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if data['type'] == 'file':
                    async with session.get(data['download_url']) as file_response:
                        if file_response.status == 200:
                            if verbose:
                                print(f"Successfully downloaded content from: {path}")
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
            
async def find_files_github(repo, path, files_pattern, token, verbose=False):
    """Searching for matching files in the GitHub repository"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    } if token else {}
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    if verbose:
        print(f"Fetching contents from {url}...")
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as response:
            if response.status != 200:
                print(f"Failed to fetch contents from {url}: {response.status}")
                return []
            contents = await response.json()
            matches = []
            if isinstance(contents, dict) and contents['type'] == 'file':
                filename = contents['name']
                for file_pattern in files_pattern:
                    if re.search(file_pattern, filename):
                        if verbose:
                            print(f"File matching pattern found: {filename}")
                        matches.append(contents['path'])
                return matches
            elif isinstance(contents, list):
                tasks = []
                for content in contents:
                    if content['type'] == 'file':
                        filename = content['name']
                        for file_pattern in files_pattern:
                            if re.search(file_pattern, filename):
                                if verbose:
                                    print(f"File matching pattern found: {filename}")
                                matches.append(content['path'])
                    elif content['type'] == 'dir':
                        tasks.append(find_files_github(repo, content['path'], files_pattern, token, verbose))
                subdir_matches = await asyncio.gather(*tasks)
                for subdir_match in subdir_matches:
                    matches.extend(subdir_match)
                return matches
            else:
                print(f"Unexpected content structure from {url}")
                return []
            
async def calculate_entropy(data):
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    frequencies = {char: data.count(char) / length for char in set(data)}
    for freq in frequencies.values():
        entropy -= freq * math.log2(freq)
    return entropy

ENTROPY_THRESHOLD = 4.5
MIN_LENGTH = 25

async def find_secrets(content, path, verbose=False):
    """Searching for secrets in the file's text using entropy check."""
    output = ""
    
    try:
        lines = content.splitlines()
        for line_number, line in enumerate(lines, start=1):
            highlighted_line = line.strip()
            found_match = False
            found_entop = False
            words = line.split()
            for word in words:
                if len(word) >= MIN_LENGTH:
                    entropy = await calculate_entropy(word)
                    if entropy > ENTROPY_THRESHOLD:
                        if verbose:
                            print(f"Secret found using entropy in {path}")
                            verbose=False
                        found_match = True
                        found_entop = True
                        highlighted_word = f"{fg('yellow')}{word}{attr(0)}"
                        highlighted_line = highlighted_line.replace(word, highlighted_word)
            if found_match:
                output += f"{highlighted_line}{' (found entropy)' if found_entop else ''} - (line {line_number})\n"
        text_found = f">>> Found in {path}\n\n"
        if output:
            output = text_found + output
        else:
            logging.info(f"[+] No secrets found in {path}")    
    except Exception as e:
        error_message = f"[-] Error occurred while reading {path}: {e}"
        logging.error(error_message)
        print(f"{fg('red')}{error_message}{attr(0)}")
    return output

async def find_files(directory, files_pattern):
    """Searching for matching files in the local repository (for testing)"""
    matches = []
    for root, _, files in os.walk(directory):
        for filename in files:
            for file_pattern in files_pattern:
                if re.search(file_pattern, filename):
                    matches.append(os.path.join(root, filename))
    return matches
        
async def get_local_file_content(file):
    async with aiofiles.open(file, "r", encoding="UTF-8") as f:
        return await f.read()
        
async def save_results_to_file(results, file_path='found_secrets.json', verbose=False):
    """Saving the results to the found_secrets.json file"""
    try:
        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(results, indent=4, ensure_ascii=False))
        logging.info(f"[+] Results saved to {file_path}")
        if verbose:
            print(f"Results saved to {file_path}")
    except Exception as e:
        logging.error(f"[-] Error while saving results to file: {e}")
        print(f"[-] Error while saving results to file: {e}")

parser = argparse.ArgumentParser()

def parse_arguments():
    """Function for processing command-line arguments"""
    parser = argparse.ArgumentParser(description="GitHub Secret Finder")
    parser.add_argument("-r", "--repo", help="Repository path")
    parser.add_argument("-t", "--token", help="GitHub token for authentication")
    parser.add_argument("-p", "--path", default="", help="Path in the repository GitHub to search (optional)")
    parser.add_argument("-l", "--local", help="Path in the local repository to search (optional)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

async def main():
    """Main function"""
    args = parse_arguments()
          
    search_file = "regex_patterns/file_paterns.csv"
    if os.path.exists(search_file):
        async with aiofiles.open(search_file, "r", encoding="UTF-8") as files:
            reg_files = await files.readlines()
            regexp_file = [reg_file.strip() for reg_file in reg_files if reg_file.strip()]
    else:
        print(f"{fg('yellow')}[-] File {search_file} is missing.{attr(0)}")
        exit(1)
    
    if args.repo:
        token = args.token if args.token else None
        if args.verbose:
            print(f"Searching in GitHub repository {args.repo}...")
        output = []
        task = []
        found_files = await find_files_github(args.repo, args.path, regexp_file, token, args.verbose)
        if not found_files:
            print(f"{fg('yellow')}[-] No files found.{attr(0)}")
            exit(1)
        
        for file in found_files:
            task.append(get_file_content(args.repo, file, token, args.verbose))
        
        contents = await asyncio.gather(*task)
        
        for content, file in zip(contents, found_files):
            if content:    
                results = await find_secrets(content, file, args.verbose)
                if results:
                    output.append(results)     
        if output:
            print("\n".join(output))
            await save_results_to_file(output, verbose=args.verbose)
        else:
            print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
                
    if args.local:
        if args.verbose:
            print(f"Searching in local repository at {args.local}...")
        output_from_local_path = []
        found_local_files = await find_files(args.local, regexp_file)
        
        tasks = [get_local_file_content(file) for file in found_local_files]
        contents = await asyncio.gather(*tasks)

        for local_content, local_file in zip(contents, found_local_files):
            if local_content:
                results_local_secrets = await find_secrets(local_content, local_file, args.verbose)
                if results_local_secrets:
                    output_from_local_path.append(results_local_secrets)     
        if output_from_local_path:
            print("\n".join(output_from_local_path))
        else:
            print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
            
if __name__ == "__main__":
    asyncio.run(main())
