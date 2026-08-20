import sys
import zlib
import struct

def compress_file(src_path, dst_path):
    with open(src_path, "rb") as f:
        raw_data = f.read()

    compressed_data = zlib.compress(raw_data, level=9)
    
    header = struct.pack("<I", len(raw_data))

    with open(dst_path, "wb") as f:
        f.write(header + compressed_data)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        compress_file(sys.argv[1], sys.argv[2])