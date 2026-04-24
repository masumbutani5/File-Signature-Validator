# ==========================================================
# File Spoof Detector - Folder Scan Only Version
# Scans all files inside a folder
# Checks extension vs real type using python-magic
# ==========================================================

import os
import magic


# ----------------------------------------------------------
# Detect real file type using python-magic
# ----------------------------------------------------------
def get_real_type(file_path):

    info = magic.from_file(file_path).upper()

    if "JPEG" in info:
        return "JPG"

    elif "PNG" in info:
        return "PNG"

    elif "PDF" in info:
        return "PDF"

    elif "ZIP" in info:
        return "ZIP"

    elif "EXECUTABLE" in info or "PE32" in info:
        return "EXE"

    else:
        return "UNKNOWN"


# ----------------------------------------------------------
# Scan all files in folder
# ----------------------------------------------------------
def scan_folder(folder_path):

    # Check if folder exists
    if not os.path.exists(folder_path):
        print("❌ Folder not found.")
        return

    print("🔍 Scanning Folder:", folder_path)

    # Read all files inside folder
    for file_name in os.listdir(folder_path):

        # Create full file path
        full_path = os.path.join(folder_path, file_name)

        # Only check files, skip subfolders
        if os.path.isfile(full_path):

            # Get file extension
            extension = os.path.splitext(full_path)[1].replace(".", "").upper()

            # Detect real type
            real_type = get_real_type(full_path)

            # Print result
            print("\n📁 File:", file_name)
            print("Extension:", extension)
            print("Detected :", real_type)

            # Compare extension with real type
            if extension == real_type:
                print("✅ File looks normal.")
            else:
                print("⚠️ Suspicious file detected!")


# ----------------------------------------------------------
# MAIN PROGRAM
# Change folder path here
# ----------------------------------------------------------
folder = r"M:/testingfolder"

scan_folder(folder)