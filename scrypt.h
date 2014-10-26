#ifndef SCRYPT_H
#define SCRYPT_H

typedef long long  int64;
typedef unsigned long long  uint64;

#include "bignum.h"
#ifdef __cplusplus
extern "C" {
#endif

void scrypt_N_1_1_256(const char* input, char* output, unsigned int Nfactor);
void scrypt_N_1_1_256_sp_generic(const char* input, char* output, char* scratchpad, unsigned int Nfactor);
#define GET_HPB(hpb) CBigNum(hpb & 0x00000000000000000000000000000000000000000000000000000000FFFFFFFF).getuint()

static inline uint32_t scrypt_le32dec(const void *pp)
{
  const uint8_t *p = (uint8_t const *)pp;
  return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	  ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void scrypt_le32enc(void *pp, uint32_t x)
{
  uint8_t *p = (uint8_t *)pp;
  p[0] = x & 0xff;
  p[1] = (x >> 8) & 0xff;
  p[2] = (x >> 16) & 0xff;
  p[3] = (x >> 24) & 0xff;
}

#ifdef __cplusplus
}
#endif

#endif
