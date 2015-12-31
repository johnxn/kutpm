#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/completion.h>

#include <kutpm.h>
#include <stuff_inoutbuf.h>
#include <sha1.h>


#define NETLINK_KUTPM 31

struct sock *nl_sk = NULL;
int pid = -1;
BYTE inout_buff[INOUTBUF_LEN];

DECLARE_COMPLETION(data_ready);

static void receive_userspace_data(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    nlh = (struct nlmsghdr*)skb->data;
    if (pid == -1) {
        pid = nlh->nlmsg_pid;
        printk(KERN_INFO "hankshake from userspace, kutpmd pid: %d.\n", pid);
        return;
    }
    memcpy(inout_buff, nlmsg_data(nlh), nlmsg_len(nlh));
    printk(KERN_INFO "receive data from userspace, length: %d", nlmsg_len(nlh));
    print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1, inout_buff, sizeof(inout_buff), true);
    complete(&data_ready);
}

static int __init kutpm_init(void) {
    printk(KERN_INFO "inserting kutpm module...\n");

    struct netlink_kernel_cfg cfg = {
        .input = receive_userspace_data,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_KUTPM, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "error creating netlink socket.\n");
        return -1;
    }
    printk(KERN_INFO "kutpm module inserted.\n");
    return 0;
}

static void __exit kutpm_exit(void) {
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO "kutpm module removed.\n");
}

int is_utpmd_ready(void) {
    if (pid == -1) return -1;
    else return 0;
}

int send_inoutbuf(void) {

    printk(KERN_INFO, "buffer to send:\n");
    print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1, inout_buff, sizeof(inout_buff), true);
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;
    skb_out = nlmsg_new(INOUTBUF_LEN, 0);
    if (!skb_out) {
        printk(KERN_ERR "failed to allcoate new skb.\n");
        return -1;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, INOUTBUF_LEN, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), inout_buff, INOUTBUF_LEN);
    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0) {
        printk(KERN_ERR "failed to send skb_out.\n");
        return -1;
    }
    return 0;
}

UTPM_RESULT kutpm_get_random(
    BYTE *out, 
    UINT32 size
) {
    UTPM_RESULT res;
    stuff_inoutbuf_get_random(size);
    if (send_inoutbuf() < 0)  return UTPM_SENT_FAIL;
    wait_for_completion(&data_ready);
    if (get_random_info(&res, out) < 0) return UTPM_ROCKEY_FAIL;
    return res;
}

UTPM_RESULT kutpm_open_oiap_session(
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven
){
    UTPM_RESULT res;   
    stuff_inoutbuf_oiap();
    if (send_inoutbuf() < 0) return UTPM_SENT_FAIL;
    wait_for_completion(&data_ready);
    if (get_oiap_info(&res, authHandle, nonceEven) < 0) return UTPM_ROCKEY_FAIL;
    return res;
}

UTPM_RESULT kutpm_open_osap_session(
    /* in */
    TPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    TPM_NONCE *nonceOddOSAP,
    /* out */
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceEvenOSAP
) {
    UTPM_RESULT res;
    stuff_inoutbuf_osap(entityType, entityValue, nonceOddOSAP);
    //printf_TPM_REQUEST(InOutBuf);
    if (send_inoutbuf() < 0) {
        return UTPM_SENT_FAIL;
    }
    wait_for_completion(&data_ready);
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OSAP);
    if (get_osap_info(&res, authHandle, nonceEven, nonceEvenOSAP)) return UTPM_ROCKEY_FAIL;
    return res;
}

UTPM_RESULT kutpm_create_wrap_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY_USAGE keyUsage,
    TPM_SECRET usageAuth,
    /* out */
    TPM_KEY *wrappedKey
) {
    UTPM_RESULT res;
    TPM_NONCE nonceOddOSAP;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceEvenOSAP;
    TPM_NONCE nonceOdd;
    TPM_ENTITY_TYPE entityType;
    UINT32 entityValue;
    UTPM_RESULT res;
    if (parentHandle == TPM_KH_SRK) {
        entityType = TPM_ET_SRK;
        entityValue = TPM_KH_SRK;
    }
    else {
        entityType = TPM_ET_KEY;
        entityValue = parentHandle;
    }
    kutpm_get_random(nonceOddOSAP.nonce, sizeof(TPM_NONCE));
    if ((res = kutpm_open_osap_session(entityType, entityValue, &nonceOddOSAP,
            &authHandle, &nonceEven, &nonceEvenOSAP)) != TPM_SUCCESS) {
        return res;
    }

    kutpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    stuff_inoutbuf_createcrapkey(parentHandle, parentAuth, usageAuth, usageAuth, keyUsage, 
            &nonceOddOSAP, &nonceEvenOSAP, &nonceEven, &nonceOdd, authHandle);
    //printf_TPM_REQUEST(InOutBuf);
    if (send_inoutbuf() < 0) {
        return UTPM_SENT_FAIL;
    }
    wait_for_completion(&data_ready);
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_CreateWrapKey);
    if (get_wrappedkey_info(&res, wrappedKey) != 0) {
        return UTPM_ROCKEY_FAIL;
    }
    return res;
}

 
UTPM_RESULT kutpm_load_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY *inKey,
    /* out */
    TPM_KEY_HANDLE *inkeyHandle
) {
    UTPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (kutpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    kutpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_loadkey(parentHandle, parentAuth, inKey,
                authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (send_inoutbuf() != 0) {
        return TPM_FAIL;
    }
    wait_for_completion(&data_ready);
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_LoadKey);
    if (get_loadkey_info(&res, inkeyHandle) != 0) {
        return TPM_FAIL;
    }
    return res;
}

UTPM_RESULT kutpm_bind_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 dataSize,
    BYTE *data,
    /* out */
    UINT32 *encDataSize,
    BYTE *encData
) {
    UTPM_RESULT res;
    RSA_PUBLIC_KEY donglePub;
    if (pubKey->keyLength != sizeof(RSA_PUBLIC_KEY)) {
        return TPM_ENCRYPT_ERROR;
    }
    memcpy(&donglePub, pubKey->key, pubKey->keyLength);
    BYTE flags[] = {0x01, 0x01, 0x00, 0x00, 0x02}; //TPM_BOUND_DATA flag.
    BYTE raw[INPUT_BLOB_SIZE];
    UINT32 rawSize = sizeof(flags) + dataSize;
    if (rawSize > INPUT_BLOB_SIZE) {
        return TPM_BAD_DATASIZE;
    }
    memcpy(raw, flags, sizeof(flags));
    memcpy(raw+sizeof(flags), data, dataSize);
    /*
    UINT32 errcode;
    if ((errcode = encrypt_with_pubkey(&donglePub, raw, rawSize, encData, encDataSize)) != DONGLE_SUCCESS) {
        printf("errcode is %x\n", errcode);
        return TPM_ENCRYPT_ERROR;
    }
    */
    if (stuff_inoutbuf_bind(&donglePub, rawSize, raw) != 0) return TPM_FAIL;
    if (send_inoutbuf() != 0) return TPM_FAIL;

    wait_for_completion(&data_ready);
    if (get_bind_info(&res, encDataSize, encData) != 0) return TPM_FAIL;
    return TPM_SUCCESS;
}

UTPM_RESULT kutpm_unbind_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 encDataSize,
    BYTE *encData,
    /* out */
    UINT32 *dataSize,
    BYTE *data
){
    UTPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (kutpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    kutpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_unbind(keyHandle, keyAuth, encData,
                encDataSize, authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (send_inoutbuf() != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }

    wait_for_completion(&data_ready);
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_UnBind);
    if (get_unbind_info(&res, dataSize, data) != 0) {
        return TPM_FAIL;
    }
    return res;

}

UTPM_RESULT kutpm_sign_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 areaToSignSize,
    BYTE *areaToSign,
    /* out */
    UINT32 *sigSize,
    BYTE *sig
) {
    UTPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (areaToSignSize != 20) {
        return TPM_BAD_PARAMETER;
    }
    if (kutpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    kutpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_sign(keyHandle, keyAuth, areaToSign,
                areaToSignSize, authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (send_inoutbuf() != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_Sign);
    wait_for_completion(&data_ready);
    if (get_sign_info(&res, sigSize, sig) != 0) {
        return TPM_FAIL;
    }
    return res;
}

UTPM_RESULT kutpm_verify_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 sigSize,
    BYTE *sig,
    UINT32 dataSize,
    BYTE *data
){
    UTPM_RESULT res;
    RSA_PUBLIC_KEY donglePub;
    if (pubKey->keyLength != sizeof(RSA_PUBLIC_KEY)) {
        return TPM_DECRYPT_ERROR;
    }
    memcpy(&donglePub, pubKey->key, pubKey->keyLength);
    BYTE raw[20];
    UINT32 rawSize = 20;
    /*
    UINT32 errcode;
    if ((errcode = decrypt_with_pubkey(&donglePub, sig, sigSize, raw, &rawSize)) != DONGLE_SUCCESS) {
        printf("errcode is %x\n", errcode);
        return TPM_DECRYPT_ERROR;
    }
    */
    if (stuff_inoutbuf_verify(&donglePub, sigSize, sig) != 0) return TPM_DECRYPT_ERROR;
    if (send_inoutbuf() != 0) return TPM_DECRYPT_ERROR;
    wait_for_completion(&data_ready);
    if (get_verify_info(&res, &rawSize, raw) != 0) return TPM_DECRYPT_ERROR;
    if (rawSize != 20 || memcmp(data, raw, 20)) return TPM_BAD_SIGNATURE;
    return TPM_SUCCESS;

}

UTPM_RESULT kutpm_make_hash(
    UINT32 dataSize,
    BYTE *data,
    TPM_DIGEST *digest
) {
    tpm_sha1_ctx_t sha1;
    tpm_sha1_init(&sha1);
    tpm_sha1_update(&sha1, data, dataSize);
    tpm_sha1_final(&sha1, digest->digest);
    return TPM_SUCCESS;
}

UTPM_RESULT kutpm_flush_specific(
    TPM_HANDLE handle,
    TPM_RESOURCE_TYPE resourceType
){
    UTPM_RESULT res;
    if (stuff_inoutbuf_flush(handle, resourceType) != 0) return TPM_FAIL;
    if (send_inoutbuf() != 0)  return TPM_FAIL;

    wait_for_completion(&data_ready);
    if (get_flush_info(&res) != 0) return TPM_FAIL;
    return res;
}

UTPM_RESULT kutpm_flush_all(void){
    UTPM_RESULT res;
    int i;
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
        if ((res = kutpm_flush_specific(0x2000000+i, TPM_RT_AUTH)) != TPM_SUCCESS) return res;
    }
    for (i = 0; i < TPM_MAX_KEYS; i++) {
        if ((res = kutpm_flush_specific(0x1000000+i, TPM_RT_KEY)) != TPM_SUCCESS) return res;
    }
    return TPM_SUCCESS;
}

UTPM_RESULT kutpm_pcr_extend(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *inDigest
) {
    UTPM_RESULT res;
    if (stuff_inoutbuf_extend(pcrNum, inDigest) != 0) return TPM_FAIL;
    if (send_inoutbuf() != 0) return TPM_FAIL;

    wait_for_completion(&data_ready);
    if (get_pcr_extend_info(&res) != 0) return TPM_FAIL;
    return res;
}

UTPM_RESULT kutpm_pcr_read(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *outDigest
) {
    UTPM_RESULT res;
    if (stuff_inoutbuf_read(pcrNum) != 0) return TPM_FAIL;
    if (send_inoutbuf() !=0) return TPM_FAIL;

    wait_for_completion(&data_ready);
    if (get_pcr_read_info(&res, outDigest) !=0) return TPM_FAIL;
    return res;
}

UTPM_RESULT kutpm_test(void) {
#if 0
    if (is_utpmd_ready() != 0) return UTPM_CONNECT_ERR;
    char buffer_to_send[INOUTBUF_LEN];
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;
    char *greetings = "hello from kernel.\n";
    int pidd;

    printk(KERN_INFO "entering: %s\n", __FUNCTION__);

    skb_out = nlmsg_new(INOUTBUF_LEN, 0);

    if (!skb_out) {
        printk(KERN_ERR "failed to allocate new skb.\n");
        return UTPM_KERNEL_ERR;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, INOUTBUF_LEN, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(buffer_to_send, greetings, strlen(greetings));
    memcpy(nlmsg_data(nlh), buffer_to_send, INOUTBUF_LEN);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0) {
        printk(KERN_ERR "failed to sent buffer.\n");
        return UTPM_SENT_FAIL;
    }
    printk(KERN_INFO "send message succeed.\n");

    wait_for_completion(&data_ready);
    nlh = (struct nlmsghdr*)skb_data;
    pidd = nlh->nlmsg_pid;
    printk(KERN_INFO "data ready.\n");
    printk(KERN_INFO "pid again %d.\n", pidd);
    return UTPM_SUCCESS;
#endif
    return 0;
}

EXPORT_SYMBOL(kutpm_test);
EXPORT_SYMBOL(kutpm_get_random);
EXPORT_SYMBOL(kutpm_open_oiap_session);
EXPORT_SYMBOL(kutpm_open_osap_session);
EXPORT_SYMBOL(kutpm_create_wrap_key);
EXPORT_SYMBOL(kutpm_load_key);
EXPORT_SYMBOL(kutpm_bind_data);
EXPORT_SYMBOL(kutpm_unbind_data);
EXPORT_SYMBOL(kutpm_sign_data);
EXPORT_SYMBOL(kutpm_verify_data);
EXPORT_SYMBOL(kutpm_make_hash);
EXPORT_SYMBOL(kutpm_flush_specific);
EXPORT_SYMBOL(kutpm_flush_all);
EXPORT_SYMBOL(kutpm_pcr_extend);
EXPORT_SYMBOL(kutpm_pcr_read);

module_init(kutpm_init);
module_exit(kutpm_exit);


MODULE_AUTHOR("johnxn <johnxn@foxmail.com>");
MODULE_LICENSE("GPL");


