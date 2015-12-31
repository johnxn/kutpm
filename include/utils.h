#ifndef _UTILS_H
#define _UTILS_H

#include "tpm_structures.h"
#include "tpm_marshalling.h"
#include "hmac.h"
#include "sha1.h"

#if 0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif

UINT32 get_in_param_offset(TPM_COMMAND_CODE ordinal);


void compute_in_parm_digest(BYTE *digest, TPM_COMMAND_CODE ordinal, BYTE *ptr, UINT32 length);
void compute_auth_data(TPM_AUTH *auth);

void compute_shared_secret(TPM_SECRET secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET sharedSecret);
void tpm_encrypt_auth_secret(TPM_SECRET plainAuth, TPM_SECRET secret, TPM_NONCE *nonce, TPM_ENCAUTH encAuth);


#endif /* _UTILS_H */

