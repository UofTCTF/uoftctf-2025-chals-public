from pwn import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import re
import ast

def die(message):
    print(message)
    s.close()
    exit(1)

def reverse(seq):
    seed = 0
    mult = 1
    nums = list(range(1, len(seq)+1))
    for i in seq:
        for j, k in enumerate(nums):
            if i == k:
                seed += mult * j
                mult *= len(nums)
                nums.pop(j)
                break
    return seed

s = remote('localhost', 5000)

welcome_message = s.recvline()
print(welcome_message.decode())

match = re.search(r'([0-9a-fA-F]+)\.', welcome_message.decode())
if not match:
    die("Failed to find the encrypted flag.")
encrypted_flag_hex = match.group(1)
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
print(f"Encrypted Flag: {encrypted_flag_hex}")

num_shuffles = 47
final_seed = None

for i in range(num_shuffles):
    # set upperbound as 30
    s.sendline(b'30')
    response = s.recvline().decode().strip()
    list_match = re.search(r'\[([^\]]+)\]', response)
    if not list_match:
        die(f"Failed to parse the shuffled list on shuffle {i+1}.")
    list_str = list_match.group(0)
    try:
        nums = ast.literal_eval(list_str)
    except Exception as e:
        die(f"Error evaluating the list on shuffle {i+1}: {e}")
    
    # Reverse the shuffle to get the seed
    seed = reverse(nums)
    print(f"Derived Seed from Shuffle {i+1}: {seed}")
    
    # Update the final seed
    final_seed = seed

# After all shuffles, derive the AES key
if final_seed is None:
    die("Failed to derive the final seed.")
    
s.close()
# Convert the seed to bytes
seed_bytes = long_to_bytes(final_seed)

# Compute the SHA-256 hash to get the AES key
key = sha256(seed_bytes).digest()
print(f"Derived AES Key: {key.hex()}")
# decrypt flag with ECB
cipher = AES.new(key, AES.MODE_ECB)
print(f"Flag: {cipher.decrypt(encrypted_flag).decode()}")