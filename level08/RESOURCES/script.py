import struct
import sys

def compute_checksum(buf, len):
    acc = 0;
    for i in range(0,len):
        term = buf[i] ^ (i & 0xFFu)
        acc ^= term
    return acc & 0xFFFF

# Define your header values
version = 1
state = 2
cmd = 5
length = 42 #max 4096
buff =  b''
checksum =  compute_checksum(buf, len):
first_byte = version | (state << 3) | (cmd << 5)

header_bytes = struct.pack('<BIH', first_byte, length, checksum)

sys.stdout.buffer.write(header_bytes)


# /* ── binary protocol header ───────────────────────────────────── */
# 8*8= 64
# typedef union {
#     uint8_t raw[8];
#     struct {
#         uint8_t  version : 3;
#         uint8_t  state   : 2;
#         uint8_t  cmd     : 3; []
#         uint32_t length;          /* payload length, little-endian  */
#         uint16_t checksum;        /* simple XOR-16 over payload      */
#     } __attribute__((packed)) fields;
# } msg_header_t;