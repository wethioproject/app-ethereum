#ifndef __ETH_CRYPTO_H__
#define __ETH_CRYPTO_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"


int eth_sign(uint32_t *path, uint32_t pathLength,
						 uint8_t *hash,
						 uint8_t *signature, uint32_t signatureLength,
						 uint8_t *parity);


#endif 
