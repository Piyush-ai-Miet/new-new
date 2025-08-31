#!/usr/bin/env python3
"""
Ghost in the Wires CTF Challenge Analyzer
=========================================

This script implements digital forensics techniques to find hidden information
that "never truly disappears" once uploaded online, as hinted in the challenge.
"""

import os
import re
import subprocess
import requests
import json
import hashlib
from urllib.parse import quote
import time
from datetime import datetime

class GhostAnalyzer:
    def __init__(self, repo_path="/home/runner/work/new-new/new-new"):
        self.repo_path = repo_path
        self.findings = []
        self.potential_flags = []
        
    def log_finding(self, category, description, data=None):
        """Log a finding for later analysis"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'description': description,
            'data': data
        }
        self.findings.append(finding)
        print(f"[{category}] {description}")
        if data:
            print(f"    Data: {data[:200]}..." if len(str(data)) > 200 else f"    Data: {data}")
    
    def search_flag_patterns(self, text, source="unknown"):
        """Search for CTF flag patterns in text"""
        if not text:
            return
            
        # Common CTF flag patterns
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',  # Generic flag pattern
            r'ghost\{[^}]+\}',
            r'GHOST\{[^}]+\}',
            r'wires\{[^}]+\}',
            r'WIRES\{[^}]+\}'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                self.potential_flags.append({
                    'flag': match,
                    'source': source,
                    'pattern': pattern
                })
                self.log_finding("FLAG_FOUND", f"Potential flag from {source}", match)
    
    def analyze_git_repository(self):
        """Analyze the git repository for hidden information"""
        print("\n=== Git Repository Analysis ===")
        
        os.chdir(self.repo_path)
        
        # Check for missing parent commit
        try:
            result = subprocess.run(['git', 'cat-file', '-p', '6dddc59df0bf3ccdae23076914301513e4ff61e3'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.log_finding("GIT_COMMIT", "Found grafted commit with missing parent", 
                               "Parent: 5268cdc8151323827b2653a82db52da4c7b80d4d")
                self.search_flag_patterns(result.stdout, "git_commit")
        except Exception as e:
            self.log_finding("ERROR", f"Git analysis error: {e}")
        
        # Try to find any hidden branches or refs
        try:
            result = subprocess.run(['git', 'for-each-ref'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log_finding("GIT_REFS", "Git references found", result.stdout)
                self.search_flag_patterns(result.stdout, "git_refs")
        except Exception as e:
            self.log_finding("ERROR", f"Git refs error: {e}")
    
    def search_web_archives(self, url="https://github.com/Piyush-ai-Miet/new-new"):
        """Search web archives for cached versions"""
        print("\n=== Web Archive Analysis ===")
        
        # Wayback Machine API
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={quote(url)}&output=json&fl=timestamp,original,statuscode"
            response = requests.get(wayback_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # Skip header row
                    self.log_finding("WAYBACK", f"Found {len(data)-1} archived snapshots", data)
                    for entry in data[1:]:  # Skip header
                        snapshot_url = f"http://web.archive.org/web/{entry[0]}/{entry[1]}"
                        self.log_finding("WAYBACK_SNAPSHOT", f"Snapshot available", snapshot_url)
                else:
                    self.log_finding("WAYBACK", "No archived snapshots found", None)
        except Exception as e:
            self.log_finding("ERROR", f"Wayback Machine error: {e}")
        
        # Try to fetch current repository content via GitHub API
        try:
            api_url = "https://api.github.com/repos/Piyush-ai-Miet/new-new"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                repo_data = response.json()
                self.log_finding("GITHUB_API", "Repository metadata", repo_data)
                self.search_flag_patterns(json.dumps(repo_data), "github_api")
        except Exception as e:
            self.log_finding("ERROR", f"GitHub API error: {e}")
    
    def analyze_file_metadata(self):
        """Analyze file metadata for hidden information"""
        print("\n=== File Metadata Analysis ===")
        
        file_path = os.path.join(self.repo_path, "new new")
        if os.path.exists(file_path):
            # File stats
            stats = os.stat(file_path)
            self.log_finding("FILE_STATS", "File metadata", {
                'size': stats.st_size,
                'mtime': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'ctime': datetime.fromtimestamp(stats.st_ctime).isoformat()
            })
            
            # File hash
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                self.log_finding("FILE_HASH", "File hashes", {
                    'md5': md5_hash,
                    'sha256': sha256_hash
                })
                
                # Search for hidden content in file
                text_content = content.decode('utf-8', errors='ignore')
                self.search_flag_patterns(text_content, "file_content")
                
                # Look for hidden characters or encoding
                if len(content) != len(text_content.encode('utf-8')):
                    self.log_finding("ENCODING", "Potential encoding anomaly detected", None)
    
    def search_github_history(self):
        """Try to find more information from GitHub using the missing commit hash"""
        print("\n=== GitHub History Search ===")
        
        # Try to fetch the missing parent commit via GitHub API
        missing_commit = "5268cdc8151323827b2653a82db52da4c7b80d4d"
        try:
            api_url = f"https://api.github.com/repos/Piyush-ai-Miet/new-new/commits/{missing_commit}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                commit_data = response.json()
                self.log_finding("GITHUB_COMMIT", "Found missing commit via API", commit_data)
                self.search_flag_patterns(json.dumps(commit_data), "github_missing_commit")
            else:
                self.log_finding("GITHUB_COMMIT", f"Missing commit not accessible: {response.status_code}", None)
        except Exception as e:
            self.log_finding("ERROR", f"GitHub commit search error: {e}")
        
        # Search for branches
        try:
            api_url = "https://api.github.com/repos/Piyush-ai-Miet/new-new/branches"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                branches_data = response.json()
                self.log_finding("GITHUB_BRANCHES", "Repository branches", branches_data)
                self.search_flag_patterns(json.dumps(branches_data), "github_branches")
        except Exception as e:
            self.log_finding("ERROR", f"GitHub branches error: {e}")
    
    def analyze_commit_messages_and_diffs(self):
        """Analyze commit messages and diffs for hidden information"""
        print("\n=== Commit Analysis ===")
        
        os.chdir(self.repo_path)
        
        # Analyze commit message for clues
        commit_msg = "Replaced a brief description of a CTF challenge with a detailed analysis request for finding hidden information."
        self.log_finding("COMMIT_MSG", "Commit message analysis", commit_msg)
        self.search_flag_patterns(commit_msg, "commit_message")
        
        # The commit message suggests there was original content that was "replaced"
        # This is a key clue that there was previous data
        self.log_finding("CLUE", "Commit suggests previous content existed", 
                        "The word 'Replaced' indicates original content was overwritten")
    
    def decode_and_analyze_patterns(self):
        """Look for encoded patterns or steganography"""
        print("\n=== Pattern and Encoding Analysis ===")
        
        # Analyze the missing commit hash for patterns
        missing_hash = "5268cdc8151323827b2653a82db52da4c7b80d4d"
        self.log_finding("HASH_ANALYSIS", "Missing commit hash analysis", missing_hash)
        
        # Try various encodings/decodings of the hash
        try:
            # Convert hex to ascii (if possible)
            hex_pairs = [missing_hash[i:i+2] for i in range(0, len(missing_hash), 2)]
            ascii_attempt = ""
            for pair in hex_pairs:
                try:
                    char_code = int(pair, 16)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        ascii_attempt += chr(char_code)
                    else:
                        ascii_attempt += "."
                except:
                    ascii_attempt += "."
            
            if ascii_attempt.strip("."):
                self.log_finding("DECODE_ATTEMPT", "Hash to ASCII conversion", ascii_attempt)
                self.search_flag_patterns(ascii_attempt, "decoded_hash")
        except Exception as e:
            self.log_finding("ERROR", f"Decoding error: {e}")
    
    def generate_report(self):
        """Generate a comprehensive report of all findings"""
        print("\n" + "="*50)
        print("GHOST IN THE WIRES - ANALYSIS REPORT")
        print("="*50)
        
        print(f"\nTotal findings: {len(self.findings)}")
        print(f"Potential flags found: {len(self.potential_flags)}")
        
        if self.potential_flags:
            print("\n=== POTENTIAL FLAGS ===")
            for flag_info in self.potential_flags:
                print(f"Flag: {flag_info['flag']}")
                print(f"Source: {flag_info['source']}")
                print(f"Pattern: {flag_info['pattern']}")
                print("-" * 30)
        
        print("\n=== KEY FINDINGS ===")
        for finding in self.findings:
            if finding['category'] in ['FLAG_FOUND', 'CLUE', 'GITHUB_COMMIT']:
                print(f"[{finding['category']}] {finding['description']}")
                if finding['data']:
                    print(f"    {finding['data']}")
        
        print("\n=== SUMMARY ===")
        print("This CTF challenge 'Ghost in the Wires' involves:")
        print("1. A git repository with grafted/shallow history")
        print("2. A missing parent commit (5268cdc8151323827b2653a82db52da4c7b80d4d)")
        print("3. Evidence of replaced/deleted content")
        print("4. The principle that 'nothing truly disappears online'")
        
        if not self.potential_flags:
            print("\nNo obvious flags found in current analysis.")
            print("The flag may be in:")
            print("- The missing commit content")
            print("- Web archive snapshots")
            print("- Encoded in metadata or hashes")
            print("- Hidden in the repository's online history")
    
    def run_full_analysis(self):
        """Run the complete analysis"""
        print("Starting Ghost in the Wires CTF Analysis...")
        print("Looking for digital traces that 'never truly disappear'...")
        
        self.analyze_git_repository()
        self.analyze_file_metadata()
        self.analyze_commit_messages_and_diffs()
        self.search_web_archives()
        self.search_github_history()
        self.decode_and_analyze_patterns()
        self.generate_report()

if __name__ == "__main__":
    analyzer = GhostAnalyzer()
    analyzer.run_full_analysis()