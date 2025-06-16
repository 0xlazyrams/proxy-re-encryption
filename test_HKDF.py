from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import binascii

# Function to derive a key using HKDF
def derive_key(ikm, salt, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    key = hkdf.derive(ikm)
    return key

# Test parameters
input_key_material = os.urandom(32)  # Random 32-byte IKM
info = b"test_context"  # Context-specific info
length = 32  # Output key length (256 bits)
salt1 = os.urandom(16)  # First random salt
salt2 = os.urandom(16)  # Different random salt
same_salt = salt1  # Same as salt1 for testing identical salt

# Test 1: Derive keys with the same salt
print("Test 1: Using the same salt")
key1_same_salt = derive_key(input_key_material, salt1, info, length)
key2_same_salt = derive_key(input_key_material, salt1, info, length)
print(f"Key 1 (salt1): {binascii.hexlify(key1_same_salt).decode()}")
print(f"Key 2 (same salt1): {binascii.hexlify(key2_same_salt).decode()}")
print(f"Keys are equal: {key1_same_salt == key2_same_salt}\n")

# Test 2: Derive keys with different salts
print("Test 2: Using different salts")
key1_diff_salt = derive_key(input_key_material, salt1, info, length)
key2_diff_salt = derive_key(input_key_material, salt2, info, length)
print(f"Key 1 (salt1): {binascii.hexlify(key1_diff_salt).decode()}")
print(f"Key 2 (salt2): {binascii.hexlify(key2_diff_salt).decode()}")
print(f"Keys are equal: {key1_diff_salt == key2_diff_salt}\n")

# Test 3: Derive keys with no salt (salt=None)
print("Test 3: Using no salt (salt=None)")
key1_no_salt = derive_key(input_key_material, None, info, length)
key2_no_salt = derive_key(input_key_material, None, info, length)
print(f"Key 1 (no salt): {binascii.hexlify(key1_no_salt).decode()}")
print(f"Key 2 (no salt): {binascii.hexlify(key2_no_salt).decode()}")
print(f"Keys are equal: {key1_no_salt == key2_no_salt}\n")

# Test 4: Compare same salt vs different salt vs no salt
print("Test 4: Comparing across salt configurations")
print(f"Same salt vs different salt: {key1_same_salt == key2_diff_salt}")
print(f"Same salt vs no salt: {key1_same_salt == key1_no_salt}")
print(f"Different salt vs no salt: {key2_diff_salt == key1_no_salt}")


"""
-----------------------------------------------------------------------------------
------------------------------ OUTPUT SAMPLE RESULTS ------------------------------
-----------------------------------------------------------------------------------

Test 1: Using the same salt
Key 1 (salt1): 681bbaa3964c9de4e0b17e433c9b999bc5b28b4bd727a3b1216f46b6f7440f64
Key 2 (same salt1): 681bbaa3964c9de4e0b17e433c9b999bc5b28b4bd727a3b1216f46b6f7440f64
Keys are equal: True

Test 2: Using different salts
Key 1 (salt1): 681bbaa3964c9de4e0b17e433c9b999bc5b28b4bd727a3b1216f46b6f7440f64
Key 2 (salt2): 5be837cbc29be7f05af05ce3c9e10eaab3c23e65cbe1a191bb1e05ff472d71c1
Keys are equal: False

Test 3: Using no salt (salt=None)
Key 1 (no salt): d50e0cdf3b90dd51ecb5b3c741fe195eecc4d3909595e91a916d4291ece67f2e
Key 2 (no salt): d50e0cdf3b90dd51ecb5b3c741fe195eecc4d3909595e91a916d4291ece67f2e
Keys are equal: True

Test 4: Comparing across salt configurations
Same salt vs different salt: False
Same salt vs no salt: False
Different salt vs no salt: False
"""