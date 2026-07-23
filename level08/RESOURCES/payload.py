import struct
import sys

def compute_checksum(buf, l):
    acc = 0
    for i in range(0,l):
        term = buf[i] ^ (i & 0xFF)
        acc ^= term
    return acc & 0xFFFF

# Define your header values
version = 1
state = 0
cmd = 0
length = 2 #max 4096
buff =  b'\xAD\xDE'
checksum =  compute_checksum(buff, length)
first_byte = version | (state << 3) | (cmd << 5)
header_bytes = struct.pack('<BIHB', first_byte, length, checksum, 0)

sys.stdout.buffer.write(header_bytes)

sys.stdout.buffer.write(buff)

version = 1
state = 0
cmd = 2
length = 2 #max 4096
buff =  b'\xAD\xDE'
checksum =  compute_checksum(buff, length)
first_byte = version | (state << 3) | (cmd << 5)
header_bytes = struct.pack('<BIHB', first_byte, length, checksum, 0)

sys.stdout.buffer.write(header_bytes)

sys.stdout.buffer.write(buff)

# level08@snowcrash:~$ python3 whily.py | nc -U  /run/blacksun/blacksun.sock 
# HELLO OK
# ACCESS GRANTED
# FLAG=s5cAhoAfNT9GrgqykhZavyBg9