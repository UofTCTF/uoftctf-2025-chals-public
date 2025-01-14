from pwn import *
from Crypto.Util.Padding import pad


def oracle(choice, blocks=[]):
    global p
    p.recvuntil(b": ")
    p.sendline(str(choice).encode())
    if choice == 1:
        return p.recvline().strip()
    p.sendline(b64e(b"".join(blocks)).encode())
    # if padding is incorrect, the server will return an error
    return b"Error" in p.recvline()


host = "localhost"
port = 5000

context.log_level = "error"
p = remote(host, port)
ciphertext = b64d(oracle(1))
iv = ciphertext[:16]
# we use the first block, since it decrypts correctly, and we can just multiply it till its length is one block greater than the padded desired plaintext (80 = 64 + 16 > 64)
ciphertext = iv * 5
blocks = [bytearray(ciphertext[i:i + 16])
          for i in range(0, len(ciphertext), 16)]

flag = b""
desired_pt = pad(
    b"I am an authenticated admin, please give me the flag", 16)  # len = 64
print("Starting decryption")
# loop backwards through blocks except for the last one
for i in range(len(blocks) - 2, -1, -1):
    block = blocks[i]
    intermediate = bytearray(16)
    flag_block = b""
    og_block = block.copy()
    for j in range(len(block) - 1, -1, -1):  # loop backwards through block
        for c in range(256):
            # if the character is the same as the original blocks value, skip it
            # this is because we already know that the original block is valid
            # only check the first iteration because we are trying to find the initial padding
            if c == og_block[j] and j == len(block) - 1:
                continue
            block[j] = c
            # send the blocks from i to i+2, since we are trying to decrypt the block i
            # padding only works if the plaintext block we are trying to decrypt is the last block
            error = oracle(2, blocks[i:i+2])
            if error:
                continue
            # get the intermediate value by xoring the padding with the character
            intermediate[j] = c ^ (16 - j)
            # set all the bytes after the current byte to the padding value for the next iteration
            block[j:] = xor(intermediate[j:], 16 - j + 1)
            print(f"Decrypting byte {j+1} in block {i+1}")
            # break if byte is found
            break
    # set the block back to the original, remember to use [:] to copy the values, otherwise it will create a new reference
    print(desired_pt[i*16:i*16+16])
    new_bytes = xor(intermediate, desired_pt[i*16:i*16+16])
    block[:] = new_bytes

# once all ciphertexts are set, we should get the flag
oracle(2, blocks)
print(p.recvline())
print(p.recvline().strip().decode())
