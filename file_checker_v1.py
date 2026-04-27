# ==========================================================
# File Spoof Detector + CSV Hash Database
# Scans folder files
# Detects extension mismatch / multiple extensions
# Saves suspicious file hashes in CSV format
# Detects repeated suspicious files
# ==========================================================

import os
import magic
import hashlib
import csv


# ----------------------------------------------------------
# Hash database file
# ----------------------------------------------------------
HASH_DB = "known_hashes.csv"


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

        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ----------------------------------------------------------
# Load saved hashes from CSV
# ----------------------------------------------------------
def load_hashes():

    hashes = set()

    if not os.path.exists(HASH_DB):
        return hashes

    with open(HASH_DB, "r", newline="") as file:

        reader = csv.reader(file)
        next(reader, None)   # Skip header

        for row in reader:
            if row:
                hashes.add(row[0])

    return hashes


# ----------------------------------------------------------
# Save new hash to CSV
# ----------------------------------------------------------
def save_hash(file_hash, file_name):

    file_exists = os.path.exists(HASH_DB)

    with open(HASH_DB, "a", newline="") as file:

        writer = csv.writer(file)

        # Write header first time
        if not file_exists:
            writer.writerow(["hash", "file_name"])

        writer.writerow([file_hash, file_name])


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

        suspicious = False
        reasons = []

        # Extension mismatch check
        if extension != real_type:
            suspicious = True
            reasons.append("Extension does not match real file type")

        # Multiple extension check
        if has_double_extension(file_name):
            suspicious = True
            reasons.append("Multiple extensions found in filename")

        print("\n==================================================")
        print("FILE NAME     :", file_name)
        print("EXTENSION     :", extension)
        print("REAL TYPE     :", real_type)

        if suspicious:

            print("THREAT LEVEL  : SUSPICIOUS")
            print("REASONS:")

            for reason in reasons:
                print("   -", reason)

            file_hash = get_file_hash(full_path)
            print("SHA256 HASH   :", file_hash)

            if file_hash in known_hashes:
                print("STATUS        : Previously detected suspicious file")

            else:
                save_hash(file_hash, file_name)
                known_hashes.add(file_hash)
                print("STATUS        : New suspicious hash saved to CSV")

        else:
            print("✅ THREAT LEVEL  : SAFE")
            print("📌 STATUS        : No suspicious activity found")

        print("==================================================")


# ----------------------------------------------------------
# MAIN PROGRAM
# ----------------------------------------------------------
folder = r"M:/test_files"

scan_folder(folder)