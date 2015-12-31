#include <linux/module.h>
#include <linux/slab.h>
#include "kutpm.h"

static void test_kutpm_get_random(void);
static void test_kutpm_open_oiap_session(void);
static void test_kutpm_open_osap_session(void);
static void test_kutpm_create_wrap_key(void);
static void test_kutpm_load_key(void);
static void test_kutpm_bind_key(void);
static void test_kutpm_unbind_key(void);
static void test_kutpm_sign_data(void);
static void test_kutpm_verify_data(void);
static void test_kutpm_make_hash(void);
static void test_kutpm_flush_specific(void);
static void test_kutpm_flush_all(void);
static void test_kutpm_pcr_extend(void);
static void test_kutpm_pcr_read(void);

static void test_kutpm_get_random(void) {
    printk(KERN_INFO "testing kutpm_get_random()...\n");
    BYTE buffer[20];
    UTPM_RESULT res;
    if ((res = kutpm_get_random(buffer, sizeof(buffer))) != UTPM_SUCCESS) {
        printk(KERN_INFO "kutpm_get_random() failed. errocde %d.\n", res);
        return;
    }
    printk(KERN_INFO "random number buffer:\n");
    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, buffer, sizeof(buffer), true);
    printk(KERN_INFO "kutpm_get_random() is working.\n");
}

static void test_kutpm_open_oiap_session(void) {

}

static void test_kutpm_open_osap_session(void) {
    printk(KERN_INFO "testing kutpm_open_osap_session()...\n");
    TPM_ENTITY_TYPE entityType;
    UINT32 entityValue;
    TPM_NONCE nonceOddOSAP;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceEvenOSAP;
    UTPM_RESULT res;

    entityType = TPM_ET_SRK;
    entityValue = TPM_KH_SRK;
    kutpm_get_random(nonceOddOSAP.nonce, sizeof(TPM_NONCE));
    if ((res = kutpm_open_osap_session(entityType, entityValue, &nonceOddOSAP, &authHandle, &nonceEven, &nonceEvenOSAP)) != UTPM_SUCCESS) {
        printk(KERN_INFO "kutpm_open_osap_session() failed. errcode %d.\n", res);
        return;
    }
    printk(KERN_INFO "kutpm_open_osap_session() is working.\n");
}

static void test_flush_all(void) {
    printk(KERN_INFO "testing kutpm_flush_all()...\n");
    UTPM_RESULT res;
    if ((res = kutpm_flush_all()) != UTPM_SUCCESS) {
        printk(KERN_INFO "kutpm_flush_all faield. errcode %d.\n", res);
        return;
    }
    printk(KERN_INFO "kutpm_flush_all() is working.\n");
}

static void test_kutpm_create_wrap_key(void) {
    printk(KERN_INFO "testing kutpm_create_wrap_key()...\n");
UTPM_KEY wrappedKey;
    UTPM_KEY_HANDLE parentHandle = UTPM_KH_SRK;
    UTPM_SECRET parentAuth= {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    UTPM_KEY_USAGE keyUsage = UTPM_KEY_SIGNING;
    UTPM_SECRET keyAuth = {0x0a, 0x0b};
    UTPM_RESULT res;
    if ((res = kutpm_create_wrap_key(parentHandle, parentAuth, keyUsage, keyAuth, &wrappedKey)) != UTPM_SUCCESS) {
        printk(KERN_INFO "create wrapped key failed.\n");
        return;
    }
    free_TPM_KEY(wrappedKey);
    printk(KERN_INFO "kutpm_create_wrap_key() is working.\n");
}

static void __init test_init(void) {
    printk(KERN_INFO "test_init().\n");
    //test_kutpm_get_random();
    //test_kutpm_open_osap_session();
    //test_flush_all();
    test_kutpm_create_wrap_key();
}

static void __exit test_exit(void) {
    printk(KERN_INFO "test_exit().\n");
}

module_init(test_init);
module_exit(test_exit);


MODULE_LICENSE("GPL");
