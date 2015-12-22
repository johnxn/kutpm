#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/completion.h>

#include <kutpm.h>
#include <stuff_inoutbuf.h>


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
        printk(KERN_INFO "hankshake from userspace, utpmd pid: %d.\n", pid);
        return;
    }
    memcpy(inout_buff, nlmsg_data(nlh), nlmsg_len(nlh));
    printk(KERN_INFO "receive data from userspace, length: %d", nlmsg_len(nlh));
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

module_init(kutpm_init);
module_exit(kutpm_exit);


MODULE_AUTHOR("johnxn <johnxn@foxmail.com>");
MODULE_LICENSE("GPL");


