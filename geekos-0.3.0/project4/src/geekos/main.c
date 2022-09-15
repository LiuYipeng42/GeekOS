/*
 * GeekOS C code entry point
 * Copyright (c) 2001,2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2004, Iulian Neamtiu <neamtiu@cs.umd.edu>
 * $Revision: 1.51 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/bootinfo.h>
#include <geekos/crc32.h>
#include <geekos/dma.h>
#include <geekos/floppy.h>
#include <geekos/ide.h>
#include <geekos/int.h>
#include <geekos/keyboard.h>
#include <geekos/kthread.h>
#include <geekos/mem.h>
#include <geekos/paging.h>
#include <geekos/pfat.h>
#include <geekos/screen.h>
#include <geekos/string.h>
#include <geekos/timer.h>
#include <geekos/trap.h>
#include <geekos/tss.h>
#include <geekos/user.h>
#include <geekos/vfs.h>

/*
 * Define this for a self-contained boot floppy
 * with a PFAT filesystem.  (Target "fd_aug.img" in
 * the makefile.)
 */
/*#define FD_BOOT*/

#ifdef FD_BOOT
#define ROOT_DEVICE "fd0"
#define ROOT_PREFIX "a"
#else
#define ROOT_DEVICE "ide0"
#define ROOT_PREFIX "c"
#endif

#define INIT_PROGRAM "/" ROOT_PREFIX "/shell.exe"

static void Mount_Root_Filesystem(void);
static void Spawn_Init_Process(void);


/*
 * Kernel C code entry point.
 * Initializes kernel subsystems, mounts filesystems,
 * and spawns init process.
 */
void Main(struct Boot_Info* bootInfo) {
    Init_BSS();
    Init_Screen();
    Init_Mem(bootInfo);
    Init_CRC32();
    Init_TSS();
    Init_Interrupts();
    Init_VM(bootInfo); // 初始化内核使用的 pde 和 pte
    Init_Scheduler();
    Init_Traps();
    Init_Timer();
    Init_Keyboard();
    Init_DMA();
    Init_Floppy();
    Init_IDE();

    Init_PFAT();  // 对 PFAT 文件系统进行初始化
	// 调用 Register_Filesystem 函数进行文件系统的注册，此函数的参数是文件系统的名字（paft）和
	// 文件系统的操作（格式化Format和挂载Mount，只传入了 PFAT_Mount 函数作为Mount操作），
	// Register_Filesystem 函数会将创建好的 Filesystem 结构加入到文件系统链表中

    Mount_Root_Filesystem();  // 对刚才创建好的 PFAT 文件系统 进行挂载

    Set_Current_Attr(ATTRIB(BLACK, GREEN | BRIGHT));
    Print("Welcome to GeekOS!\n");
    Set_Current_Attr(ATTRIB(BLACK, GRAY));

    Spawn_Init_Process();

    /* Now this thread is done. */
    Exit(0);
}

static void Mount_Root_Filesystem(void) {

	int res = Mount(ROOT_DEVICE, ROOT_PREFIX, "pfat"); // 挂载 Init_PFAT 函数中创建的 PFAT 文件系统 Filesystem 结构
	// 1. 首先调用了 Lookup_Filesystem 通过传入的文件系统的名字在文件系统链表中查找到对应的 Filesystem 结构
	// 2. 然后创建一个 mountPoint 挂载点，将此函数传入 Filesystem 结构的 ops 属性的 
	//    Mount操作函数（实则为PFAT_Mount 函数）中进行文件系统的挂载
	// 3. 在 PFAT_Mount 函数中会调用 PFAT_Register_Paging_File 函数进行 paging device 的注册
	// 4. PFAT_Register_Paging_File 函数则调用了 Register_Paging_Device 函数进行注册，
	//    此函数会把创建的 pagingDevice 赋值给一个全局变量 s_pagingDevice，在 Init_Paging 函数中会使用这个变量进行初始化

    if (res != 0)  
        Print("Failed to mount /" ROOT_PREFIX " filesystem\n");
    else
        Print("Mounted /" ROOT_PREFIX " filesystem!\n");

    Init_Paging();
}

static void Spawn_Init_Process(void) {
    //  ("Spawn the init process");
    const char* command = "shell.exe";
    struct Kernel_Thread* pThread;
    int sh_pid = Spawn(INIT_PROGRAM, command, &pThread);
    if (sh_pid == 0) {
        Print("Failed to spawn init process: error code = %d\n", sh_pid);
    } else {
        Join(pThread);
    }
}
