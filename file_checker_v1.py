# Importing os module to work with file paths and extensions
import os


# Function to detect REAL file type using magic number (file signature)
def get_file_type(file_path):

    # Dictionary storing known magic numbers and their file types
    # Key = file signature in bytes
    # Value = file type name
    signatures = {
        b'\x4D\x5A': 'EXE',        # "MZ" header → Windows executable file
        b'\x25\x50\x44\x46': 'PDF', # %PDF → PDF document
        b'\xFF\xD8\xFF': 'JPG',     # JPEG image file
        b'\x89\x50\x4E\x47': 'PNG', # PNG image file
        b'\x50\x4B\x03\x04': 'ZIP'  # ZIP compressed file
    }

    # Open the file in binary mode (rb = read binary)
    # Because magic numbers are stored in binary format
    with open(file_path, 'rb') as f:

        # Read first 4 bytes of the file (this contains the magic number)
        file_header = f.read(4)

    # Loop through all known signatures in dictionary
    for sig, filetype in signatures.items():

        # Check if file starts with this signature
        if file_header.startswith(sig):

            # If match found, return the correct file type
            return filetype

    # If no signature matches, return Unknown
    return "Unknown"


# Function to compare real file type with file extension
def check_file(file_path):

    # Get actual file type using magic number detection
    real_type = get_file_type(file_path)

    # Extract file extension from file name
    # Example: "file.jpg" → "jpg"
    extension = os.path.splitext(file_path)[1].replace('.', '').upper()

    # Print file information
    print(f"\nFile: {file_path}")
    print(f"Extension: {extension}")
    print(f"Detected Type: {real_type}")

    # Check if file type does NOT match extension
    # AND file type is not unknown
    if real_type != "Unknown" and real_type != extension:

        # If mismatch found → suspicious file
        print("⚠️ Suspicious: File type mismatch detected!")

    else:
        # If everything matches → normal file
        print("✅ File looks normal.")


# ---------------- MAIN PROGRAM ----------------

# File path to test (change this file when testing)
file = "M:/SkinInstaller.jpg"

# Run the file checker function
check_file(file)