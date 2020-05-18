/*******************************************************************************
*   Ledger Ethereum App
*   (c) 2016-2020 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include "chainConfig.h"
#include "ethUstream.h"
#include "tokens.h"

#define WEI_TO_ETHER 18
#define MAX_BIP32_PATH 10

/*-------------------------------------------------------*/

typedef struct internalStorage_t {
unsigned char dataAllowed;
unsigned char contractDetails;
uint8_t initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t*) PIC(&N_storage_real))
/*-------------------------------------------------------*/

typedef struct tokenContext_t {
    uint8_t data[4 + 32 + 32];
    uint32_t dataFieldPos;
} tokenContext_t;

typedef struct rawDataContext_t {
    uint8_t data[32];
    uint8_t fieldIndex;
    uint8_t fieldOffset;
} rawDataContext_t;

typedef union {
    tokenContext_t tokenContext;
    rawDataContext_t rawDataContext;
} dataContext_t;
extern dataContext_t dataContext;
/*-------------------------------------------------------*/

typedef struct publicKeyContext_t {
    cx_ecfp_public_key_t publicKey;
    uint8_t address[41];
    uint8_t chainCode[32];
    bool getChaincode;
} publicKeyContext_t;

typedef struct transactionContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[32];
    tokenDefinition_t currentToken;
} transactionContext_t;

typedef struct messageSigningContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[32];
    uint32_t remainingLength;
} messageSigningContext_t;

typedef union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
    messageSigningContext_t messageSigningContext;
} tmpCtx_t;
extern tmpCtx_t tmpCtx;
/*-------------------------------------------------------*/

typedef enum {
APP_STATE_IDLE,
APP_STATE_SIGNING_TX,
APP_STATE_SIGNING_MESSAGE
} app_state_t;
/*-------------------------------------------------------*/

typedef struct strData_t {
    char fullAddress[43];
    char fullAmount[50];
    char maxFee[50];
} strData_t;

typedef struct strDataTmp_t {
    char tmp[100];
    char tmp2[40];
} strDataTmp_t;

typedef struct swap_data_s {
    char destination_address[65];
    unsigned char amount[32];
    unsigned char fees[32];
    int was_address_checked;
} swap_data_t;

typedef union {
    strData_t common;
    strDataTmp_t tmp;
    swap_data_t swap_data;
} display_variables_t;

extern display_variables_t strings;
/*-------------------------------------------------------*/

typedef union {
txContent_t txContent;
cx_sha256_t sha2;
} tmpContent_t;
extern tmpContent_t tmpContent;
/*-------------------------------------------------------*/

extern txContext_t txContext;
/*-------------------------------------------------------*/

extern chain_config_t *chainConfig;
/*-------------------------------------------------------*/

typedef struct {
    uint8_t dataAllowed;
    uint8_t contractDetails;
    uint8_t appState;
    char addressSummary[32];
    bool dataPresent;
    bool tokenProvisioned;
    bool currentTokenSet;
    uint8_t called_from_swap;
} appCtx_t;

extern volatile appCtx_t appCtx;
/*-------------------------------------------------------*/

void app_main(void);
void app_context_init();

#endif /* _GLOBALS_H_ */