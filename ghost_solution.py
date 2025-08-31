#!/usr/bin/env python3
"""
Ghost in the Wires CTF Solution
===============================

This script analyzes the discovered information from the git history
and attempts to solve the CTF challenge.
"""

import re
import requests
import base64
import hashlib
from urllib.parse import quote, unquote
import json

class GhostSolver:
    def __init__(self):
        self.original_content = """https://cybersecure-x.ctfd.io/challenges#Ghost%20in%20the%20Wires-36 it is the ctf file lnk of the osint 


as if hints Ghost in the Wires
150
They say once something is uploaded online, it never truly disappears. Can you find what was left behind by this OC?

you have to find the flag"""
        
        self.ctf_url = "https://cybersecure-x.ctfd.io/challenges#Ghost%20in%20the%20Wires-36"
        self.findings = []
        
    def log_finding(self, title, content):
        """Log a finding"""
        print(f"\n[FINDING] {title}")
        print(f"Content: {content}")
        self.findings.append((title, content))
    
    def search_flag_patterns(self, text, source=""):
        """Search for flag patterns in text"""
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'ghost\{[^}]+\}',
            r'GHOST\{[^}]+\}',
            r'wires\{[^}]+\}',
            r'WIRES\{[^}]+\}',
            r'osint\{[^}]+\}',
            r'OSINT\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}'
        ]
        
        flags_found = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in ['flag{...}', 'FLAG{...}']:  # Skip example patterns
                    flags_found.append(match)
                    self.log_finding(f"FLAG FOUND in {source}", match)
        
        return flags_found
    
    def analyze_url_components(self):
        """Analyze the CTF URL for hidden information"""
        print("\n=== URL Analysis ===")
        
        url = self.ctf_url
        self.log_finding("Original CTF URL", url)
        
        # Extract components
        if "#Ghost%20in%20the%20Wires-36" in url:
            decoded_fragment = unquote("Ghost%20in%20the%20Wires-36")
            self.log_finding("URL Fragment Decoded", decoded_fragment)
            
            # The number 36 might be significant
            self.log_finding("Challenge Number", "36")
            
            # Try various encodings of "36"
            self.analyze_number_36()
    
    def analyze_number_36(self):
        """Analyze the significance of number 36"""
        print("\n=== Number 36 Analysis ===")
        
        # ASCII value 36 is '$'
        self.log_finding("ASCII 36", chr(36))
        
        # Binary representation
        binary_36 = bin(36)[2:]
        self.log_finding("Binary 36", binary_36)
        
        # Hex representation
        hex_36 = hex(36)[2:]
        self.log_finding("Hex 36", hex_36)
        
        # Try base64 encoding of "36"
        encoded_36 = base64.b64encode(b"36").decode()
        self.log_finding("Base64 of '36'", encoded_36)
    
    def analyze_commit_hash_patterns(self):
        """Analyze the commit hashes for patterns"""
        print("\n=== Commit Hash Analysis ===")
        
        original_commit = "5268cdc8151323827b2653a82db52da4c7b80d4d"
        replaced_commit = "6dddc59df0bf3ccdae23076914301513e4ff61e3"
        
        self.log_finding("Original Commit Hash", original_commit)
        self.log_finding("Replacement Commit Hash", replaced_commit)
        
        # Look for patterns in the hashes
        self.search_flag_patterns(original_commit, "original_commit_hash")
        self.search_flag_patterns(replaced_commit, "replacement_commit_hash")
        
        # Try XORing the hashes
        try:
            orig_int = int(original_commit, 16)
            repl_int = int(replaced_commit, 16)
            xor_result = orig_int ^ repl_int
            xor_hex = hex(xor_result)[2:]
            self.log_finding("XOR of commit hashes", xor_hex)
            self.search_flag_patterns(xor_hex, "xor_hashes")
        except:
            pass
    
    def analyze_author_info(self):
        """Analyze the author information for clues"""
        print("\n=== Author Analysis ===")
        
        author = "piyush dhariwal <piyush.dhariwal.cse.2023@miet.ac.in>"
        self.log_finding("Author Information", author)
        
        # Extract components
        name = "piyush dhariwal"
        email = "piyush.dhariwal.cse.2023@miet.ac.in"
        institution = "miet.ac.in"
        year = "2023"
        
        self.log_finding("Author Name", name)
        self.log_finding("Email", email)
        self.log_finding("Institution", institution)
        self.log_finding("Year", year)
        
        # Search for patterns in author info
        self.search_flag_patterns(author, "author_info")
    
    def analyze_original_content_patterns(self):
        """Analyze the original content for hidden patterns"""
        print("\n=== Original Content Analysis ===")
        
        content = self.original_content
        self.log_finding("Full Original Content", content)
        
        # Search for flags in original content
        self.search_flag_patterns(content, "original_content")
        
        # Look for steganography or hidden patterns
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.strip():
                self.log_finding(f"Line {i+1}", line.strip())
        
        # The phrase "OC" might be significant - Original Creator?
        if "OC" in content:
            self.log_finding("OC Reference", "OC likely means 'Original Creator'")
        
        # The number 150 might be significant
        if "150" in content:
            self.log_finding("Number 150 found", "150")
            self.analyze_number_150()
    
    def analyze_number_150(self):
        """Analyze the significance of number 150"""
        print("\n=== Number 150 Analysis ===")
        
        # ASCII value 150 (but it's > 127, so extended ASCII)
        try:
            self.log_finding("Extended ASCII 150", chr(150))
        except:
            pass
        
        # Binary representation
        binary_150 = bin(150)[2:]
        self.log_finding("Binary 150", binary_150)
        
        # Hex representation
        hex_150 = hex(150)[2:]
        self.log_finding("Hex 150", hex_150)
        
        # Convert to character if possible
        if 32 <= 150 <= 126:
            self.log_finding("ASCII Character 150", chr(150))
    
    def try_flag_constructions(self):
        """Try to construct flags from discovered patterns"""
        print("\n=== Flag Construction Attempts ===")
        
        # Common flag formats with discovered elements
        elements = ["ghost", "wires", "36", "150", "osint", "piyush", "miet"]
        
        for elem in elements:
            # Try basic flag format
            flag_attempt = f"flag{{{elem}}}"
            self.log_finding("Flag Attempt", flag_attempt)
            
            # Try with uppercase
            flag_attempt_upper = f"flag{{{elem.upper()}}}"
            self.log_finding("Flag Attempt (Upper)", flag_attempt_upper)
            
            # Try with numbers
            flag_attempt_num = f"flag{{{elem}36}}"
            self.log_finding("Flag Attempt (with 36)", flag_attempt_num)
            
            flag_attempt_num2 = f"flag{{{elem}150}}"
            self.log_finding("Flag Attempt (with 150)", flag_attempt_num2)
    
    def analyze_ctf_platform_clues(self):
        """Analyze clues related to the CTF platform"""
        print("\n=== CTF Platform Analysis ===")
        
        platform = "cybersecure-x.ctfd.io"
        self.log_finding("CTF Platform", platform)
        
        # The platform name itself might contain clues
        self.search_flag_patterns(platform, "platform_name")
        
        # "cybersecure-x" might be significant
        platform_parts = platform.split('.')
        for part in platform_parts:
            self.log_finding("Platform Component", part)
            self.search_flag_patterns(part, "platform_component")
    
    def generate_comprehensive_report(self):
        """Generate a final report with all findings"""
        print("\n" + "="*60)
        print("GHOST IN THE WIRES - COMPREHENSIVE SOLUTION REPORT")
        print("="*60)
        
        print("\n=== DISCOVERED ORIGINAL CONTENT ===")
        print("Through git forensics, we recovered the original content that was 'replaced':")
        print(self.original_content)
        
        print("\n=== KEY DISCOVERIES ===")
        print("1. Original CTF URL: https://cybersecure-x.ctfd.io/challenges#Ghost%20in%20the%20Wires-36")
        print("2. Challenge number: 36")
        print("3. Mystery number: 150")
        print("4. Challenge type: OSINT")
        print("5. Reference to 'OC' (Original Creator)")
        
        print("\n=== ALL FINDINGS ===")
        for title, content in self.findings:
            if "FLAG FOUND" in title:
                print(f"🚩 {title}: {content}")
            else:
                print(f"• {title}: {content}")
        
        print("\n=== SOLUTION METHODOLOGY ===")
        print("This CTF challenge demonstrates the principle that 'nothing truly disappears online':")
        print("1. Used git history analysis to find the 'replaced' content")
        print("2. Recovered the original commit that was hidden by git grafting")
        print("3. Found the original CTF platform URL and challenge details")
        print("4. Analyzed numerical patterns (36, 150) for potential flag components")
        
        print("\n=== POTENTIAL FLAG LOCATIONS ===")
        print("The actual flag might be found by:")
        print("1. Visiting the CTF platform URL if accessible")
        print("2. Combining discovered elements (ghost, wires, 36, 150)")
        print("3. Further analysis of the author's digital footprint")
        print("4. Looking for additional hidden commits or branches")
    
    def run_complete_analysis(self):
        """Run the complete CTF solution analysis"""
        print("Ghost in the Wires CTF - Complete Analysis")
        print("=" * 50)
        
        self.analyze_url_components()
        self.analyze_commit_hash_patterns()
        self.analyze_author_info()
        self.analyze_original_content_patterns()
        self.try_flag_constructions()
        self.analyze_ctf_platform_clues()
        self.generate_comprehensive_report()

if __name__ == "__main__":
    solver = GhostSolver()
    solver.run_complete_analysis()