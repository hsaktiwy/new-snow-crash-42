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
# print(hex(checksum))
header_bytes = struct.pack('<BIHB', first_byte, length, checksum, 0)
sys.stdout.buffer.write(header_bytes)
#get the hello XD

version = 1
state = 0
cmd = 2
length = 2 #max 4096
buff =  b'\xAD\xDE'
checksum =  compute_checksum(buff, length)
first_byte = version | (state << 3) | (cmd << 5)
# print(hex(checksum))
header_bytes = struct.pack('<BIHB', first_byte, length, checksum, 0)
sys.stdout.buffer.write(header_bytes)
# sys.stdout.bufer.write(buff)

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

# /* ── state identifiers ────────────────────────────────────────── */
# typedef enum __attribute__((packed)) {
#     STATE_INIT  = 0,
#     STATE_AUTH  = 1,
#     STATE_ADMIN = 2,
# } conn_state_t;

# /* ── commands ─────────────────────────────────────────────────── */
#define CMD_HELLO  0
#define CMD_AUTH   1
#define CMD_ADMIN  2
#define CMD_QUIT   3

# } msg_header_t;