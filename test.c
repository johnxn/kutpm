#include <linux/module.h>
#include "kutpm.h"

extern UTPM_RESULT kutpm_test(void);
extern UTPM_RESULT kutpm_get_random(BYTE *out, UINT32 size);

static void __init test_init(void) {
    int i;
    /*
    printk(KERN_INFO "test_init().\n");
    if (kutpm_test() != 0) {
        printk(KERN_INFO "kutpm_test() failed.\n");
    }
    */
    BYTE random_array[20];
    memset(random_array, 0, sizeof(random_array));
    if (kutpm_get_random(random_array, sizeof(random_array)) != UTPM_SUCCESS) {
        printk(KERN_ERR "kutpm_get_random() failed.\n");
        return;
    }
    for (i = 0; i < sizeof(random_array); i++) {
        printk(KERN_INFO "random_array %d: %x\n", i, 0xff & random_array[i]);
    }
}

static void __exit test_exit(void) {
    printk(KERN_INFO "test_exit().\n");
}

module_init(test_init);
module_exit(test_exit);


MODULE_LICENSE("GPL");
