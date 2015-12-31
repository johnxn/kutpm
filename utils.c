#include "utils.h"

UINT32 get_in_param_offset(TPM_COMMAND_CODE ordinal)
{
  switch (ordinal) {
    case TPM_ORD_ActivateIdentity:
    case TPM_ORD_ChangeAuth:
    case TPM_ORD_ChangeAuthAsymStart:
    case TPM_ORD_CMK_ConvertMigration:
    case TPM_ORD_CMK_CreateBlob:
    case TPM_ORD_CMK_CreateKey:
    case TPM_ORD_ConvertMigrationBlob:
    case TPM_ORD_CreateMigrationBlob:
    case TPM_ORD_CreateWrapKey:
    case TPM_ORD_Delegate_CreateKeyDelegation:
    case TPM_ORD_DSAP:
    case TPM_ORD_EstablishTransport:
    case TPM_ORD_EvictKey:
    case TPM_ORD_FlushSpecific:
    case TPM_ORD_GetAuditDigestSigned:
    case TPM_ORD_GetPubKey:
    case TPM_ORD_KeyControlOwner:
    case TPM_ORD_LoadKey:
    case TPM_ORD_LoadKey2:
    case TPM_ORD_MigrateKey:
    case TPM_ORD_Quote:
    case TPM_ORD_Quote2:
    case TPM_ORD_ReleaseTransportSigned:
    case TPM_ORD_SaveKeyContext:
    case TPM_ORD_Seal:
    case TPM_ORD_Sealx:
    case TPM_ORD_SetRedirection:
    case TPM_ORD_Sign:
    case TPM_ORD_TickStampBlob:
    case TPM_ORD_UnBind:
    case TPM_ORD_Unseal:
    case TPM_ORD_DAA_Join:
    case TPM_ORD_DAA_Sign:
      return 4;

    case TPM_ORD_CertifyKey:
    case TPM_ORD_CertifyKey2:
    case TPM_ORD_ChangeAuthAsymFinish:
      return 8;

    case TPM_ORD_OSAP:
      return 26;

    default:
      return 0;
  }
}

void compute_in_parm_digest(BYTE *digest, TPM_COMMAND_CODE ordinal, BYTE *ptr, UINT32 length) {
    ptr += get_in_param_offset(ordinal);
    length -= get_in_param_offset(ordinal);
    tpm_sha1_ctx_t sha1;
    tpm_sha1_init(&sha1);
    tpm_sha1_update_be32(&sha1, ordinal);
    tpm_sha1_update(&sha1, ptr, length);
    tpm_sha1_final(&sha1, digest);
}

void compute_auth_data(TPM_AUTH *auth) {
    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, auth->secret, sizeof(auth->secret));
    tpm_hmac_update(&ctx, auth->digest, sizeof(auth->digest));
    tpm_hmac_update(&ctx, auth->nonceEven.nonce, sizeof(auth->nonceEven.nonce));
    tpm_hmac_update(&ctx, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
    tpm_hmac_update(&ctx, &auth->continueAuthSession, 1);
    tpm_hmac_final(&ctx, auth->auth);
}

void compute_shared_secret(TPM_SECRET secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET sharedSecret) {
    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, secret, sizeof(TPM_SECRET));
    tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
    tpm_hmac_final(&ctx, sharedSecret);
}

void tpm_encrypt_auth_secret(TPM_SECRET plainAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_ENCAUTH encAuth)
{
  unsigned int i;
  tpm_sha1_ctx_t ctx;
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, secret, sizeof(TPM_SECRET));
  tpm_sha1_update(&ctx, nonce->nonce, sizeof(nonce->nonce));
  tpm_sha1_final(&ctx, encAuth);
  for (i = 0; i < sizeof(TPM_SECRET); i++)
    encAuth[i] ^= plainAuth[i];
}

