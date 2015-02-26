#include "types.h"

#include <arpa/inet.h>

uint16_t uint16be_to_host(uint16_t_be val)
{
  return ntohs(val.data);
}

uint32_t uint32be_to_host(uint32_t_be val)
{
  return ntohl(val.data);
}

uint64_t uint64be_to_host(uint64_t_be val)
{
  if (ntohs(0x00ff) == 0xff00) { /* little-endian */
    uint32_t bottom = val.data & 0xffffffff;
    uint32_t top = val.data >> 32;
    uint64_t ret = ntohl(bottom);
    ret <<= 32;
    ret |= ntohl(top);
    return ret;
  } else { /* big-endian */
    return val.data;
  }
}

uint16_t_be uint16host_to_be(uint16_t val)
{
  uint16_t_be result = { htons(val) };
  return result;
}

uint32_t_be uint32host_to_be(uint32_t val)
{
  uint32_t_be result = { htonl(val) };
  return result;
}

uint64_t_be uint64host_to_be(uint64_t val)
{
  if (ntohs(0x00ff) == 0xff00) { /* little-endian */
    uint32_t bottom = val & 0xffffffff;
    uint32_t top = val >> 32;
    uint64_t_be ret = { htonl(bottom) };
    ret.data <<= 32;
    ret.data |= htonl(top);
    return ret;
  } else { /* big-endian */
    uint64_t_be ret = { val };
    return ret;
  }
}

