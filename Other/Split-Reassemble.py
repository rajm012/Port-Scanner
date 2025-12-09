
"""
Uncomment the below code to reassemble the file and comment below to for the same.
"""

# ------------To assemble----------

# def reassemble_file(output_file, chunk_prefix):
#     """
#     Reassembles a file from smaller chunks.

#     :param output_file: Path to the output file.
#     :param chunk_prefix: Prefix of the chunk files (e.g., "dist/main.exe.part").
#     """
#     part_num = 1
#     with open(output_file, "wb") as f:
#         while True:
#             chunk_file = f"{chunk_prefix}{part_num}"
#             try:
#                 with open(chunk_file, "rb") as part:
#                     f.write(part.read())
#                 print(f"Added chunk: {chunk_file}")
#                 part_num += 1
#             except FileNotFoundError:
#                 print("All chunks have been reassembled.")
#                 break

# if __name__ == "__main__":
    
#     output_file = "dist/gui_assembled.exe"
#     chunk_prefix = "dist/gui.exe.part"
#     reassemble_file(output_file, chunk_prefix)



# --------------------To split------------

# def split_file(file_path, chunk_size):
#     """
#     Splits a file into smaller chunks.

#     :param file_path: Path to the file to split.
#     :param chunk_size: Size of each chunk in bytes.
#     """
#     part_num = 1
#     with open(file_path, "rb") as f:
#         while chunk := f.read(chunk_size):
#             with open(f"{file_path}.part{part_num}", "wb") as part:
#                 part.write(chunk)
#             print(f"Created chunk: {file_path}.part{part_num}")
#             part_num += 1

# if __name__ == "__main__":
#     file_path = "dist/gui.exe"

#     # Size of each chunk (e.g., 23 MB)
#     chunk_size = 23 * 1024 * 1024
#     split_file(file_path, chunk_size)
