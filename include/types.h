#ifndef TYPES_H
#define TYPES_H

#include <inttypes.h>

typedef struct {
  uint16_t data;
} uint16_t_be;

typedef struct {
  uint32_t data;
} uint32_t_be;

typedef struct {
  uint64_t data;
} uint64_t_be;

uint16_t uint16be_to_host(uint16_t_be val);
uint32_t uint32be_to_host(uint32_t_be val);
uint64_t uint64be_to_host(uint64_t_be val);

uint16_t_be uint16host_to_be(uint16_t val);
uint32_t_be uint32host_to_be(uint32_t val);
uint64_t_be uint64host_to_be(uint64_t val);

#endif

