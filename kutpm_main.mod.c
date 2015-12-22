#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x11c92bdf, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x3fa58ef8, __VMLINUX_SYMBOL_STR(wait_for_completion) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x575333d1, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
	{ 0xf611726f, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x96777e46, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x8909cf34, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0xd28e5ec5, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x19a9e62b, __VMLINUX_SYMBOL_STR(complete) },
	{ 0x2662fd02, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "7961D2176C1097590F00E7E");
