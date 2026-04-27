# File Signature Validator

A Python-based cybersecurity tool that scans files in a folder and detects suspicious or spoofed files by comparing the file extension with the actual file type using file signatures (magic numbers).

This project helps identify files that may be disguised by attackers, such as an executable file renamed as `.jpg`.

---

## Features

* Scan all files inside a selected folder
* Detect extension mismatch (example: `.jpg` file that is actually `.exe`)
* Detect multiple extensions (example: `photo.jpg.exe`)
* Identify real file type using `python-magic`
* Generate SHA256 hash for suspicious files
* Store suspicious hashes in CSV database
* Detect repeated suspicious files
* Export scan results to `scan_report.csv`
* Command line support

---

## Technologies Used

* Python 3
* `python-magic`
* CSV
* SHA256 Hashing
* File Signature Analysis

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/File-Signature-Validator.git
cd File-Signature-Validator
```

### 2. Install Required Library

```bash
pip install python-magic-bin
```

> For Linux systems:

```bash
pip install python-magic
```

---

## Usage

Run the scanner from terminal:

```bash
python file_type_validator.py M:/test_files
```

Example:

```bash
python file_type_validator.py C:/Users/Downloads
```

---

## Example Output

```text
FILE NAME    : SkinInstaller.jpg
LOCATION     : M:\test_files\sunset.jpg
EXTENSION    : JPG
REAL TYPE    : EXE

THREAT LEVEL : SUSPICIOUS
REASONS:
- Extension mismatch

SHA256 HASH  : 4c293c445a2ea041e9f96076dc51951fe77f31d709194d4b6e31f9d3cb220f6a
STATUS       : Previously detected suspicious file
```

---

## Generated Files

### known_hashes.csv

Stores hashes of suspicious files for future detection.

### scan_report.csv

Stores full scan history including:

* Date and time
* File name
* File location
* Extension
* Real file type
* Threat level
* Reasons
* SHA256 hash

---

## Use Cases

* Detect disguised malware files
* Scan downloaded files
* Basic incident response checks
* File validation in shared folders
* Cybersecurity learning project

---

## Future Improvements

* Recursive subfolder scanning
* Better false positive handling
* GUI version
* PDF report export
* Threat score levels

---

## Disclaimer

This tool is for educational and defensive security purposes only.

---

## Author

Developed by Masum Butani
