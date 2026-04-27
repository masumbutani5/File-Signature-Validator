# ==========================================================
# File Spoof Detector + CSV Hash Database + Scan Report + CLI
# ==========================================================

import os
import csv
import sys
import magic
import hashlib
from datetime import datetime


# ----------------------------------------------------------
# Database files
# ----------------------------------------------------------
HASH_DB = "known_hashes.csv"
REPORT_FILE = "scan_report.csv"


# ----------------------------------------------------------
# Detect real file type
# ----------------------------------------------------------
def get_real_type(file_path):

    info = magic.from_file(file_path).upper()

    if "JPEG" in info:
        return "JPG"
    if "PNG" in info:
        return "PNG"
    if "PDF" in info:
        return "PDF"
    if "ZIP" in info:
        return "ZIP"
    if "EXECUTABLE" in info or "PE32" in info:
        return "EXE"

    return "UNKNOWN"


# ----------------------------------------------------------
# Detect multiple extensions
# ----------------------------------------------------------
def has_double_extension(file_name):

    return file_name.count(".") > 1


# ----------------------------------------------------------
# Generate SHA256 hash
# ----------------------------------------------------------
def get_file_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ----------------------------------------------------------
# Load known hashes
# ----------------------------------------------------------
def load_hashes():

    if not os.path.exists(HASH_DB):
        return set()

    hashes = set()

    with open(HASH_DB, "r", newline="") as file:
        reader = csv.reader(file)
        next(reader, None)

        for row in reader:
            if row:
                hashes.add(row[0])

    return hashes


# ----------------------------------------------------------
# Save suspicious hash
# ----------------------------------------------------------
def save_hash(file_hash, file_name):

    new_file = not os.path.exists(HASH_DB)

    with open(HASH_DB, "a", newline="") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow(["hash", "file_name"])

        writer.writerow([file_hash, file_name])


# ----------------------------------------------------------
# Save scan report
# ----------------------------------------------------------
def save_report(file_name, file_path, extension, real_type, level, reasons, file_hash):

    new_file = not os.path.exists(REPORT_FILE)

    with open(REPORT_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow([
                "date_time",
                "file_name",
                "file_location",
                "extension",
                "real_type",
                "threat_level",
                "reasons",
                "sha256_hash"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_name,
            file_path,
            extension,
            real_type,
            level,
            reasons,
            file_hash
        ])


# ----------------------------------------------------------
# Scan folder
# ----------------------------------------------------------
def scan_folder(folder_path):

    if not os.path.exists(folder_path):
        print("Folder not found.")
        return

    known_hashes = load_hashes()

    print("Scanning Folder:", folder_path)

    for file_name in os.listdir(folder_path):

        full_path = os.path.join(folder_path, file_name)

        if not os.path.isfile(full_path):
            continue

        extension = os.path.splitext(file_name)[1].replace(".", "").upper()
        real_type = get_real_type(full_path)

        reasons = []

        if extension != real_type:
            reasons.append("Extension mismatch")

        if has_double_extension(file_name):
            reasons.append("Multiple extensions")

        print("\n==================================================")
        print("FILE NAME    :", file_name)
        print("LOCATION     :", full_path)
        print("EXTENSION    :", extension)
        print("REAL TYPE    :", real_type)

        file_hash = ""

        if reasons:

            print("THREAT LEVEL : SUSPICIOUS")
            print("REASONS:")

            for reason in reasons:
                print("-", reason)

            file_hash = get_file_hash(full_path)
            print("SHA256 HASH  :", file_hash)

            if file_hash in known_hashes:
                print("STATUS       : Previously detected suspicious file")
            else:
                save_hash(file_hash, file_name)
                known_hashes.add(file_hash)
                print("STATUS       : New suspicious hash saved")

            level = "SUSPICIOUS"

        else:
            print("THREAT LEVEL : SAFE")
            print("STATUS       : No suspicious activity found")
            level = "SAFE"

        save_report(
            file_name,
            full_path,
            extension,
            real_type,
            level,
            "; ".join(reasons),
            file_hash
        )

        print("==================================================")


# ----------------------------------------------------------
# MAIN PROGRAM (CLI)
# Usage: python scanner.py M:/test_files
# ----------------------------------------------------------
if len(sys.argv) < 2:
    print("Usage: python scanner.py <folder_path>")
else:
    folder = sys.argv[1]
    scan_folder(folder)