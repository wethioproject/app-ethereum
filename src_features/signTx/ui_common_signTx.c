#include "shared_context.h"
#include "utils.h"
#include "ui_callbacks.h"
#include "eth_crypto.h"

unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e) {
    uint8_t signature[100];
    uint32_t tx = 0;
    uint32_t v = getV(&tmpContent.txContent);
    uint8_t parity = 0;
    eth_sign(tmpCtx.transactionContext.bip32Path, tmpCtx.transactionContext.pathLength, 
        tmpCtx.transactionContext.hash,
        signature, sizeof(signature),
        &parity);
    // Parity is present in the sequence tag in the legacy API
    if (tmpContent.txContent.vLength == 0) {
      // Legacy API
      G_io_apdu_buffer[0] = 27;
    }
    else {
      // New API
      // Note that this is wrong for a large v, but the client can always recover
      G_io_apdu_buffer[0] = (v * 2) + 35;
    }
    if (parity) {
      G_io_apdu_buffer[0]++;
    }
    format_signature_out(signature);
    tx = 65;
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    reset_app_context();
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e) {
    reset_app_context();
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_data_ok(const bagl_element_t *e) {
    parserStatus_e txResult = USTREAM_FINISHED;
    txResult = continueTx(&txContext);
    switch (txResult) {
    case USTREAM_SUSPENDED:
        break;
    case USTREAM_FINISHED:
        break;
    case USTREAM_PROCESSING:
        io_seproxyhal_send_status(0x9000);
        ui_idle();
        break;
    case USTREAM_FAULT:
        reset_app_context();
        io_seproxyhal_send_status(0x6A80);
        ui_idle();
        break;
    default:
        PRINTF("Unexpected parser status\n");
        reset_app_context();
        io_seproxyhal_send_status(0x6A80);
        ui_idle();
    }

    if (txResult == USTREAM_FINISHED) {
        finalizeParsing(false);
    }

    return 0;
}

unsigned int io_seproxyhal_touch_data_cancel(const bagl_element_t *e) {
    reset_app_context();
    io_seproxyhal_send_status(0x6985);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

