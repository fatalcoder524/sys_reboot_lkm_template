#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/kallsyms.h>

// require KPROBES when building as MODULE
#ifdef MODULE
#ifndef CONFIG_KPROBES
#error "Building as LKM requires KPROBES."
#endif
#else
#error "only LKM builds are allowed"
#endif

#include "arch.h"

// SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
//		void __user *, arg)
// lkm_handle_sys_reboot(magic1, magic2, cmd, arg);
// PLAN
// magic1 main magic
// magic2 command
// arg, data input

#define DEF_MAGIC 0x999
#define PAUSE_SPOOF 0
#define CONTINUE_SPOOF 1

struct basic_payload {
	unsigned long reply_ptr;
	char text[256];
};

static u32 su_sid;
static u32 kernel_sid;
static atomic_t disable_spoof = ATOMIC_INIT(0);

// seems this isnt exported on some kernels
typedef int (*secctx_to_secid_fn)(const char *secdata, u32 seclen, u32 *secid);
static secctx_to_secid_fn secctx_to_secid = NULL;

static int handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	if (magic1 != DEF_MAGIC)
		return 0;

	int ok = DEF_MAGIC; // we just write magic on reply

	pr_info("avc_spoof: intercepted call! magic: 0x%d id: 0x%d\n", magic1, magic2);

	if (magic2 == PAUSE_SPOOF) {
		struct basic_payload basic = {0};
		if (copy_from_user(&basic, arg, sizeof(struct basic_payload)))
			return 0;

		pr_info("avc_spoof: pausing selinux spoof\n");
		atomic_set(&disable_spoof, 1);

		if (copy_to_user((void __user *)basic.reply_ptr, &ok, sizeof(ok)))
			return 0;
	}

	if (magic2 == CONTINUE_SPOOF) {
		struct basic_payload basic = {0};
		if (copy_from_user(&basic, arg, sizeof(struct basic_payload)))
			return 0;

		pr_info("avc_spoof: continue selinux spoof\n");
		atomic_set(&disable_spoof, 0);

		if (copy_to_user((void __user *)basic.reply_ptr, &ok, sizeof(ok)))
			return 0;
	}

	return 0;
}

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (atomic_read(&disable_spoof))
		return 0;

	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (tsid == su_sid) {
		pr_info("avc_spoof/slow_avc_audit: replacing su_sid: %u with kernel_sid: %u\n", su_sid, kernel_sid);
		PT_REGS_PARM2(regs) = (u32)kernel_sid;
	}

	pr_info("avc_spoof/slow_avc_audit: replacing su_sid: %u with kernel_sid: %u\n", su_sid, kernel_sid);
	return 0;
}

static struct kprobe slow_avc_audit_kp = {
	.symbol_name = "slow_avc_audit",
	.pre_handler = slow_avc_audit_pre_handler,
};

// https://github.com/ilammy/ftrace-hook/blob/master/ftrace_hook.c
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long retval;

	if (register_kprobe(&kp) < 0) 
		return 0;

	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}

static int get_sid(void)
{
	// dont load at all if we cant get sids
	int err = secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: su_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: su_sid: %u", su_sid);

	err = secctx_to_secid("u:r:kernel:s0", strlen("u:r:kernel:s0"), &kernel_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: kernel_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: kernel_sid: %u", kernel_sid);
	return 0;
}

static int sys_reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user *arg = (void __user *)PT_REGS_SYSCALL_PARM4(real_regs);

	return handle_sys_reboot(magic1, magic2, cmd, arg);
}

static struct kprobe sys_reboot_kp = {
	.symbol_name = SYS_REBOOT_SYMBOL,
	.pre_handler = sys_reboot_handler_pre,
};

static int __init avc_spoof_init(void) 
{
	pr_info("avc_spoof/init: with magic: 0x%x\n", (int)DEF_MAGIC);

	unsigned long addr = lookup_name("security_secctx_to_secid");
	if (!addr) {
		pr_info("avc_spoof/init: security_secctx_to_secid address not found!\n");
		return -EAGAIN;
	}

	pr_info("avc_spoof/init: security_secctx_to_secid found on: 0x%lx\n", addr);	

	// confirm symbol
	char buf[64] = {0};
	sprint_symbol(buf, addr);
	buf[63] = '\0';

	if (!!strncmp(buf, "security_secctx_to_secid", strlen("security_secctx_to_secid"))) {
		pr_info("avc_spoof/init: wrong symbol!? %s found!\n", buf);
		return -EAGAIN;
	}

	pr_info("avc_spoof/init: sprint_symbol 0x%lx: %s\n", addr, buf);
	secctx_to_secid = (secctx_to_secid_fn)addr;

	int ret = get_sid();
	if (ret) {
		pr_info("avc_spoof/init: sid grab fail, unloading!\n");
		return -EAGAIN;
	}

	ret = register_kprobe(&sys_reboot_kp);
	pr_info("avc_spoof/init: register sys_reboot kprobe: %d\n", ret);
	if (ret) {
		pr_info("avc_spoof/init: register sys_reboot fail, unloading!\n");
		return -EAGAIN;
	}

	ret = register_kprobe(&slow_avc_audit_kp);
	pr_info("avc_spoof/init: register slow_avc_audit_kp kprobe: %d\n", ret);
	if (ret) {
		unregister_kprobe(&sys_reboot_kp);
		pr_info("avc_spoof/init: register slow_avc_audit fail, unloading!\n");
		return -EAGAIN;
	}

	return 0;
}

static void __exit avc_spoof_exit(void) 
{
	unregister_kprobe(&sys_reboot_kp);
	unregister_kprobe(&slow_avc_audit_kp);
	pr_info("avc_spoof/exit: bye!\n");
}

module_init(avc_spoof_init);
module_exit(avc_spoof_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("kprobe hooked avc spoofing");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
