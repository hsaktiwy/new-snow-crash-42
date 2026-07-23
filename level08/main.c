#include <stdint.h>
#include <stdio.h>

uint16_t compute_checksum(uint8_t buf[], uint32_t len)
{
    uint16_t acc = 0;
    for (uint32_t i = 0; i < len; i++)
        acc ^= (uint16_t)buf[i] ^ (uint16_t)(i & 0xFFu);
    return acc;
}


int main()
{
    uint8_t buff[2] = {0xDE, 0xAD}; 
    printf("%x", compute_checksum(buff, 2));
}