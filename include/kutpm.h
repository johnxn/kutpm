#ifndef __KUTPM_H
#define __KUTPM_H

#include "utpm_structures.h"

#define   INOUTBUF_LEN          1020
#define   ENCRYPTED_BLOB_SIZE   256
#define   INPUT_BLOB_SIZE       241

#define WELL_KNOWN_SECRET "\x01\x02\x03\x04\x05\x06"

int is_utpmd_ready(void);

UTPM_RESULT kutpm_test(void);

UTPM_RESULT kutpm_get_random(
    BYTE *out,
    UINT32 size
);

UTPM_RESULT kutpm_open_oiap_session(
    UTPM_AUTHHANDLE *authHandle,
    UTPM_NONCE *nonceEven
);

UTPM_RESULT kutpm_open_osap_session(
    /* in */
    UTPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    UTPM_NONCE *nonceOddOSAP,
    /* out */
    UTPM_AUTHHANDLE *authHandle,
    UTPM_NONCE *nonceEven,
    UTPM_NONCE *nonceEvenOSAP
);

UTPM_RESULT kutpm_create_wrap_key(
    /* in */
    UTPM_KEY_HANDLE parentHandle,
    UTPM_SECRET parentAuth,
    UTPM_KEY_USAGE keyUsage,
    UTPM_SECRET usageAuth,
    /* out */
    UTPM_KEY *wrappedKey
);

UTPM_RESULT kutpm_load_key(
    /* in */
    UTPM_KEY_HANDLE parentHandle,
    UTPM_SECRET parentAuth,
    UTPM_KEY *inKey,
    /* out */
    UTPM_KEY_HANDLE *inkeyHandle
);

UTPM_RESULT kutpm_bind_data(
    /* in */
    UTPM_STORE_PUBKEY *pubKey,
    UINT32 dataSize,
    BYTE *data,
    /* out */
    UINT32 *encDataSize,
    BYTE *encData
);

UTPM_RESULT kutpm_unbind_data(
    /* in */
    UTPM_KEY_HANDLE keyHandle,
    UTPM_SECRET keyAuth,
    UINT32 encDataSize,
    BYTE *encData,
    /* out */
    UINT32 *dataSize,
    BYTE *data
);
 
UTPM_RESULT kutpm_sign_data(
    /* in */
    UTPM_KEY_HANDLE keyHandle,
    UTPM_SECRET keyAuth,
    UINT32 areaToSignSize,
    BYTE *areaToSign,
    /* out */
    UINT32 *sigSize,
    BYTE *sig
);
 
UTPM_RESULT kutpm_verify_data(
    /* in */
    UTPM_STORE_PUBKEY *pubKey,
    UINT32 sigSize,
    BYTE *sig,
    UINT32 dataSize,
    BYTE *data
);

UTPM_RESULT kutpm_make_hash(
    UINT32 dataSize,
    BYTE *data,
    UTPM_DIGEST *digest
);

UTPM_RESULT kutpm_flush_specific(
    UTPM_HANDLE handle,
    UTPM_RESOURCE_TYPE resourceType
);

UTPM_RESULT kutpm_flush_all(void);

UTPM_RESULT kutpm_pcr_extend(
    UTPM_PCRINDEX pcrNum,
    UTPM_DIGEST *inDigest
);

UTPM_RESULT kutpm_pcr_read(
    UTPM_PCRINDEX pcrNum,
    UTPM_DIGEST *outDigest
);



#endif
