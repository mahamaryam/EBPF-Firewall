import sys

def to_little_endian_bytes(n):
    return [n & 0xff, (n >> 8) & 0xff]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 reduction.py <port>")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
        if port < 0 or port > 65535:
            raise ValueError("Port must be between 0 and 65535.")
    except ValueError as e:
        print(f"Invalid port: {e}")
        sys.exit(1)

    le_bytes = to_little_endian_bytes(port)
    print(f"To store in bpftool, enter key: {le_bytes[0]} {le_bytes[1]}")

