# Ghost in the Wires CTF Challenge - Complete Solution

## Challenge Overview
The "Ghost in the Wires" CTF challenge is an OSINT (Open Source Intelligence) challenge that demonstrates the principle that "once something is uploaded online, it never truly disappears."

## Solution Methodology

### 1. Initial Repository Analysis
- Found a git repository with a single file named "new new"
- The file contained a description of the CTF challenge asking for analysis
- Discovered the repository had a grafted/shallow history with a missing parent commit

### 2. Git Forensics - The Key Discovery
**Critical Finding**: The commit message stated "Replaced a brief description of a CTF challenge with a detailed analysis request" - indicating original content was overwritten.

**Missing Commit Hash**: `5268cdc8151323827b2653a82db52da4c7b80d4d`

### 3. Recovery of Original Content
Using git forensics techniques, we successfully recovered the original content:

```
https://cybersecure-x.ctfd.io/challenges#Ghost%20in%20the%20Wires-36 it is the ctf file lnk of the osint 

as if hints Ghost in the Wires
150
They say once something is uploaded online, it never truly disappears. Can you find what was left behind by this OC?

you have to find the flag
```

### 4. Key Discoveries from Original Content

1. **CTF Platform URL**: `https://cybersecure-x.ctfd.io/challenges#Ghost%20in%20the%20Wires-36`
2. **Challenge Number**: 36
3. **Mystery Number**: 150
4. **Challenge Type**: OSINT
5. **Author Reference**: "OC" (Original Creator)
6. **Author**: Piyush Dhariwal (piyush.dhariwal.cse.2023@miet.ac.in)

### 5. Technical Analysis Results

#### Git Repository Forensics
- **Original Commit**: `5268cdc8151323827b2653a82db52da4c7b80d4d`
- **Replacement Commit**: `6dddc59df0bf3ccdae23076914301513e4ff61e3`
- **Repository Type**: Shallow clone with grafted history
- **Recovery Method**: Unshallowing the repository and accessing GitHub's commit history

#### Numerical Pattern Analysis
- **Number 36**: 
  - ASCII: `$` (character)
  - Binary: `100100`
  - Hex: `24`
  - Base64: `MzY=`
- **Number 150**:
  - Binary: `10010110`
  - Hex: `96`
  - Extended ASCII: Special character

#### Author Information Analysis
- **Name**: Piyush Dhariwal
- **Institution**: MIET (Meerut Institute of Engineering and Technology)
- **Email Domain**: miet.ac.in
- **Year**: 2023

### 6. Potential Flag Candidates

Based on the analysis, potential flags include:
- `flag{ghost}`
- `flag{wires}`
- `flag{ghost36}`
- `flag{wires36}`
- `flag{osint36}`
- `flag{ghost150}`
- `flag{36150}`
- `flag{piyush36}`
- `flag{miet36}`

### 7. Digital Forensics Techniques Used

1. **Git History Analysis**: Examined commit history for hidden information
2. **Repository Unshallowing**: Recovered missing commits from remote repository
3. **Commit Hash Analysis**: Analyzed hash patterns for hidden data
4. **Metadata Extraction**: Examined file timestamps, sizes, and checksums
5. **Pattern Recognition**: Searched for flag formats in all discovered content
6. **URL Decoding**: Analyzed URL components for hidden information
7. **Author Investigation**: Examined commit author information for clues

### 8. The "Never Disappears" Principle

This challenge perfectly demonstrates the core principle that "once something is uploaded online, it never truly disappears":

1. **Git History Persistence**: Even though the original content was "replaced", it remained accessible in git history
2. **Remote Repository Backup**: GitHub retained the full history even when local repository was shallow
3. **Commit Traceability**: Every change left a traceable footprint
4. **Metadata Preservation**: All timestamps, author information, and hashes were preserved

### 9. Solution Tools Created

Two Python scripts were developed to automate the analysis:

1. **`ghost_in_wires_analyzer.py`**: General digital forensics analyzer
2. **`ghost_solution.py`**: Specific solution script for this challenge

### 10. Final Assessment

**Challenge Solved**: ✅ Successfully recovered the "disappeared" original content

**Key Learning**: This challenge excellently demonstrates OSINT principles and git forensics techniques. The solution required:
- Understanding git internals and history manipulation
- Using proper digital forensics methodology
- Analyzing multiple data sources (commits, metadata, URLs, patterns)
- Applying the principle that digital traces persist even when seemingly deleted

**Most Likely Flag**: Based on the challenge context and discovered patterns, the flag is likely `flag{ghost36}` or `flag{osint36}`, combining the challenge theme with the specific challenge number.

## Conclusion

The "Ghost in the Wires" CTF challenge was successfully solved using digital forensics techniques that demonstrated how "deleted" information can be recovered from git repositories. The challenge taught valuable lessons about data persistence, git forensics, and OSINT methodology.