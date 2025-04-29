#!/usr/bin/python3
import struct

def find_little_endian_representation(num):
    """ Convert number to bytes and ensure it reconstructs correctly """
    if num < 0 or num > 0xFFFFFFFF:
        raise ValueError("Number must be in range 0 to 4,294,967,295 (32-bit unsigned)")

    # Convert number to little-endian byte order
    byte_rep = struct.pack("<I", num)  # Convert to 4-byte little-endian format

    # Extract bytes and remove unnecessary leading zeros
    non_zero_bytes = [b for b in byte_rep if b != 0]
    
    # Ensure valid reconstruction
    reconstructed_value = sum(val * (256 ** i) for i, val in enumerate(non_zero_bytes))
    assert reconstructed_value == num, "Error in reconstruction"

    return non_zero_bytes

# Get user input
user_input = int(input("Enter a number: "))
byte_values = find_little_endian_representation(user_input)

# Display byte representation that preserves value under little-endian conversion
print(f"Reduced form (little-endian bytes): {byte_values}")
print(f"To store in bpftool, enter key: {' '.join(map(str, byte_values))}")

