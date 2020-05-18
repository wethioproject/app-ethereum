#include "globals.h"

/**
* Initialize the application context on boot
*/
void app_context_init() {
    PRINTF("Context init\n");
    os_memset((uint8_t*)&appCtx, 0, sizeof(appCtx));
    os_memset((uint8_t*)&txContext, 0, sizeof(txContext));
    os_memset((uint8_t*)&tmpContent, 0, sizeof(tmpContent));

    if (N_storage.initialized != 0x01) {
    internalStorage_t storage;
    storage.dataAllowed = 0x00;
    storage.contractDetails = 0x00;
    storage.initialized = 0x01;
    nvm_write(&N_storage, (void*)&storage, sizeof(internalStorage_t));
    }

    appCtx.dataAllowed = N_storage.dataAllowed;
    appCtx.contractDetails = N_storage.contractDetails;

}