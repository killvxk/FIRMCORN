from pwn import *

elf = ELF("cgibin")

print type(elf.got)


print elf.got
for key, value in elf.got.items():
    print key , value