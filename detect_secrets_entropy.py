import os
import re
import json
from colored import fg, attr
import logging
import aiohttp
import asyncio
import argparse
import math


logging.basicConfig(filename='scan_results.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', filemode='w')

async def get_file_content(repo, path, verbose=False):
    """Function for retrieving the content of files from GitHub"""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    if verbose:
        print(f"Fetching file content from: {path}")
    
    async with aiohttp.ClientSession() as session:
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
            
def calculate_entropy(data):
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

async def find_secrets(t_regexp, content, path):
    """Searching for secrets in the file's text using entropy check."""
    output = ""
    
    try:
        lines = content.splitlines()
        for line_number, line in enumerate(lines, start=1):
            highlighted_line = line.strip()
            found_match = False
            found_entop = False
            
            # Search by regular expressions
            for regexp in t_regexp:
                matches = re.findall(regexp, line)
                if matches:
                    found_match = True
                    for match in matches:
                        highlighted_match = f"{fg('light_green')}{match}{attr(0)}"
                        highlighted_line = highlighted_line.replace(match, highlighted_match)
            
            # Additional search for strings with high entropy (if string length >= MIN_LENGTH)
            words = line.split()
            for word in words:
                if len(word) >= MIN_LENGTH:
                    entropy = calculate_entropy(word)
                    if entropy > ENTROPY_THRESHOLD:
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

def find_files(directory, files_pattern):
    """Searching for matching files in the local repository (for testing)"""
    matches = []
    for root, _, files in os.walk(directory):
        for filename in files:
            for file_pattern in files_pattern:
                if re.search(file_pattern, filename):
                    matches.append(os.path.join(root, filename))
    return matches


async def find_files_github(repo, path, files_pattern, verbose=False):
    """Searching for matching files in the GitHub repository"""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    
    if verbose:
        print(f"Fetching contents from {url}...")

    async with aiohttp.ClientSession() as session:
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
                        tasks.append(find_files_github(repo, content['path'], files_pattern, verbose))
                subdir_matches = await asyncio.gather(*tasks)
                for subdir_match in subdir_matches:
                    matches.extend(subdir_match)
                return matches
            
            else:
                print(f"Unexpected content structure from {url}")
                return []
        
def save_results_to_file(results, file_path='found_secrets.json', verbose=False):
    """Saving the results to the found_secrets.json file"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logging.info(f"[+] Results saved to {file_path}")
        if verbose:
            print(f"Results saved to {file_path}")
    except Exception as e:
        logging.error(f"[-] Error while saving results to file: {e}")
        print(f"{fg('red')}[-] Error while saving results to file: {e}{attr(0)}")

parser = argparse.ArgumentParser()

def parse_arguments():
    """Function for processing command-line arguments"""
    parser = argparse.ArgumentParser(description="GitHub Secret Finder")
    parser.add_argument("-r", "--repo", required=True, help="Repository path")
    parser.add_argument("-p", "--path", default="", help="Path in the repository to search (optional)")
    parser.add_argument("-re", "--regex", nargs="+", default=None, help="One or more regular expressions to search for secrets (optional)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

async def main():
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
            print(f"{fg('yellow')}[-] File {regexp_to_search} is missing.{attr(0)}")
            exit(1)
          
    search_file = "regex_patterns/file_paterns.csv"
    if os.path.exists(search_file):
        if args.verbose:
            print(f"Loading file patterns from {search_file}...")
        with open(search_file, "r", encoding="UTF-8") as f:
            reg_files = f.readlines()
            regexp_file = [reg_file.strip() for reg_file in reg_files if reg_file.strip()]
    else:
        print(f"{fg('yellow')}[-] File {search_file} is missing.{attr(0)}")
        exit(1)
        
    found_files = await find_files_github(args.repo, args.path, regexp_file, args.verbose)
    if not found_files:
        print(f"{fg('yellow')}[-] No files found.{attr(0)}")
        exit(1)
    
    output = []
    task = []
    
    for file in found_files:
        task.append(get_file_content(args.repo, file, args.verbose))
    
    contents = await asyncio.gather(*task)
    
    for content, file in zip(contents, found_files):
        if content:    
            results = await find_secrets(t_regexp, content, file)
            if results:
                output.append(results)
            
    if output:
        print("\n".join(output))
        save_results_to_file(output, verbose=args.verbose)
    else:
        print(f"{fg('yellow')}[-] No secrets found.{attr(0)}")
  
        
if __name__ == "__main__":
    asyncio.run(main())
