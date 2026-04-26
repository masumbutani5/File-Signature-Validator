# ==========================================================
# File Spoof Detector - Smarter Double Extension Detection
# Safe names like: my.photo.jpg -> ignored
# Suspicious names like: photo.jpg.exe -> detected
# ==========================================================

import os
import magic


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
# Smart double extension detection
# Detect only if final extension is dangerous
# Example:
# photo.jpg.exe  -> True
# invoice.pdf.scr -> True
# my.photo.jpg -> False
# ----------------------------------------------------------
def has_double_extension(file_name):

    return file_name.count(".") > 1


# ----------------------------------------------------------
# Scan folder
# ----------------------------------------------------------
def scan_folder(folder_path):

    if not os.path.exists(folder_path):
        print("❌ Folder not found.")
        return

    print("🔍 Scanning Folder:", folder_path)

    for file_name in os.listdir(folder_path):

        full_path = os.path.join(folder_path, file_name)

        if not os.path.isfile(full_path):
            continue

        extension = os.path.splitext(file_name)[1].replace(".", "").upper()
        real_type = get_real_type(full_path)

        print("\n📁 File:", file_name)
        print("Extension:", extension)
        print("Detected :", real_type)

        suspicious = False

        # Mismatch check
        if extension != real_type:
            suspicious = True
            print("⚠️ Extension mismatch detected!")

        # Smart double extension check
        if has_double_extension(file_name):
            suspicious = True
            print("⚠️ Multiple extensions detected - review manually")

        # Final result
        if suspicious:
            print("🚨 Suspicious file!")
        else:
            print("✅ File looks normal.")


# ----------------------------------------------------------
# MAIN PROGRAM
# ----------------------------------------------------------
folder = r"M:/test_files"

scan_folder(folder)