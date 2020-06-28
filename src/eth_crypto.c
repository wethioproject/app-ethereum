#include "eth_crypto.h"
#include "os_io_seproxyhal.h"

static const uint8_t const SECP256K1_N[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41 };

void  rng_rfc6979(unsigned char *rnd, 
                     unsigned char *h1,
                     unsigned char *x, unsigned int x_len, 
                     const unsigned char *q, unsigned int q_len, 
                     unsigned char *V, unsigned char *K) {
  unsigned int      h_len, offset,found,i;
  cx_hmac_sha256_t hmac;

  h_len = 32;
    //a. h1 as input
 
    //loop for a candidate
  found = 0;
  while (!found) {
    if(x) {
        //b.  Set:          V = 0x01 0x01 0x01 ... 0x01
      os_memset(V, 0x01, h_len);
        //c. Set: K = 0x00 0x00 0x00 ... 0x00
      os_memset(K, 0x00, h_len);
        //d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
      V[h_len]= 0;
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, 0,       V, h_len+1, K, 0);
      cx_hmac(&hmac, 0,       x, x_len, K, 0);
      cx_hmac(&hmac, CX_LAST, h1, h_len, K, 32);
        //e.  Set: V = HMAC_K(V) 
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac((cx_hmac_t *)&hmac, CX_LAST, V,    h_len, V, 32);
        //f.  Set:  K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) 
      V[h_len]= 1;
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, 0,       V, h_len+1, K, 0);
      cx_hmac(&hmac, 0,       x, x_len, K, 0);
      cx_hmac(&hmac, CX_LAST, h1, h_len, K, 32);
        //g. Set: V = HMAC_K(V) --
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
        // initial setup only once
      x = NULL;
    } else {
        // h.3  K = HMAC_K(V || 0x00) 
      V[h_len] = 0;
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, CX_LAST, V, h_len+1, K, 32);
        // h.3 V = HMAC_K(V)
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
    }

    //generate candidate
    /* Shortcut: As only secp256k1/sha256 is supported, the step h.2 :
     *   While tlen < qlen, do the following:
     *     V = HMAC_K(V)
     *     T = T || V
     * is replace by 
     *     V = HMAC_K(V)
     */
    x_len = q_len;
    offset = 0;
    while (x_len) {
      if (x_len<h_len) {
        h_len = x_len;
      }
      cx_hmac_sha256_init(&hmac, K, 32);
      cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
      os_memmove(rnd+offset, V, h_len);
      x_len -= h_len;
    }

    // h.3 Check T is < n
    for (i = 0; i< q_len; i++) {  
      if (V[i]<q[i]) { 
        found = 1;
        break;
      }
    }
  }
}


int eth_sign(uint32_t *path, uint32_t pathLength,
						 uint8_t *hash,
						 uint8_t *signature, uint32_t signatureLength,
						 uint8_t *parity) {

	uint8_t privateKeyData[32];
	cx_ecfp_private_key_t privateKey;
	int tries = 0;
	uint8_t V[33];
	uint8_t K[32];	
	unsigned int infos = 0;

	io_seproxyhal_io_heartbeat();
	os_perso_derive_node_bip32(CX_CURVE_256K1, path, pathLength, privateKeyData, NULL);
	cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
	for (;;) {
		io_seproxyhal_io_heartbeat();		
		if (tries == 0) {
			rng_rfc6979(signature, privateKeyData, privateKey.d, privateKey.d_len, SECP256K1_N, 32, V, K);
		}   
		else {
			rng_rfc6979(signature, privateKeyData, NULL, 0, SECP256K1_N, 32, V, K);
		}     
		io_seproxyhal_io_heartbeat();		
		cx_ecdsa_sign(&privateKey, CX_RND_PROVIDED | CX_LAST, CX_SHA256,
                    hash,
                    32, signature, signatureLength, &infos);
		if ((infos & CX_ECCINFO_xGTn) == 0) {
			break;
		}		
		tries++;
	}
	os_memset(privateKeyData, 0, sizeof(privateKeyData));
	os_memset(&privateKey, 0, sizeof(privateKey));
	*parity = (infos & CX_ECCINFO_PARITY_ODD);
	return 1;
}
