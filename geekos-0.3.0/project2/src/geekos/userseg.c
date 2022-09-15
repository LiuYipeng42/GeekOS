/*
 * Segmentation-based user mode implementation
 * Copyright (c) 2001,2003 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.23 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/argblock.h>
#include <geekos/defs.h>
#include <geekos/gdt.h>
#include <geekos/int.h>
#include <geekos/kassert.h>
#include <geekos/kthread.h>
#include <geekos/ktypes.h>
#include <geekos/malloc.h>
#include <geekos/mem.h>
#include <geekos/segment.h>
#include <geekos/string.h>
#include <geekos/tss.h>
#include <geekos/user.h>

/* ----------------------------------------------------------------------
 * Variables
 * ---------------------------------------------------------------------- */

#define DEFAULT_USER_STACK_SIZE 8192

/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */

/*
 * Create a new user context of given size
 */

/* TODO: Implement
static struct User_Context* Create_User_Context(ulong_t size)
*/
static struct User_Context* Create_User_Context(ulong_t size) {
    struct User_Context* userContext;
	// 首先将地址转化为可以整除页的地址
    size = Round_Up_To_Page(size);
    userContext = (struct User_Context*)Malloc(sizeof(struct User_Context)); // 创建一个 UserContext
    /* 内存分配成功则继续为 userContext 下的 memory 分配内存空间 */
    if (userContext == NULL) {
        return NULL;
    }
    userContext->memory = (char*)Malloc(size); // memory 是一个指向用户进程内存的指针，所以要根据传进来的 size 参数分配一个内存空间
    if (userContext->memory == NULL) {
        Free(userContext);
        return NULL;
    }
    memset(userContext->memory, '\0', size);  // 将 memory 指向的内存空间的值清零
    userContext->size = size;

	// GDT 与 LDT p56-58
    /* 新建一个 LDT 描述符， */
	// Allocate_Segment_Descriptor 函数会从 GDT 中找到一个空余的描述符并返回，
    // 用于保存此用户进程内存空间的基地址
    userContext->ldtDescriptor = Allocate_Segment_Descriptor();
    if (userContext->ldtDescriptor == NULL) {
        Free(userContext->memory);
        return NULL;
    }
    /* 初始化段描述符 */
    Init_LDT_Descriptor(userContext->ldtDescriptor, userContext->ldt,
                        NUM_USER_LDT_ENTRIES);
    /* 新建一个 LDT 选择子 */
	// 逻辑地址：16位的选择子（本质上是选择符表的索引） + 16位的段内地址
    // 内核进程对象 Kernel_Thread 的 userContext 字段会指向一个用户进程的 userContext，
    // 若内核想要访问此用户进程的内存空间，就可以根据此 ldtSelector，就可在 GDT 中查找到对应的段地址
    userContext->ldtSelector = Selector(KERNEL_PRIVILEGE, true, Get_Descriptor_Index(userContext->ldtDescriptor));

    /* 新建一个代码段描述符，并放入此进程的 LDT 描述符表中 */
    Init_Code_Segment_Descriptor(&userContext->ldt[0],
                                 (ulong_t)userContext->memory, size / PAGE_SIZE,
                                 USER_PRIVILEGE);
    /* 新建一个数据段描述符，并放入此进程的 LDT 描述符表中 */
    Init_Data_Segment_Descriptor(&userContext->ldt[1],
                                 (ulong_t)userContext->memory, size / PAGE_SIZE,
                                 USER_PRIVILEGE);
    /* 新建数据段和代码段选择子，用于在此进程的 LDT 描述符表找到数据段或代码段 */
    userContext->csSelector = Selector(USER_PRIVILEGE, false, 0);
    userContext->dsSelector = Selector(USER_PRIVILEGE, false, 1);

    /* 将引用数清零 */
    userContext->refCount = 0;

    return userContext;
}

static bool Validate_User_Memory(struct User_Context* userContext,
                                 ulong_t userAddr,
                                 ulong_t bufSize) {
    ulong_t avail;

    if (userAddr >= userContext->size)
        return false;

    avail = userContext->size - userAddr;
    if (bufSize > avail)
        return false;

    return true;
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* userContext) {
    /*
     * Hints:
     * - you need to free the memory allocated for the user process
     * - don't forget to free the segment descriptor allocated
     *   for the process's LDT
     */
    // TODO("Destroy a User_Context");
    // project2 Destroy_User_Context
    KASSERT(userContext->refCount == 0);
    /* 释放 LDT descriptor */
    Free_Segment_Descriptor(userContext->ldtDescriptor);
    /* 释放内存空间 */
    Disable_Interrupts();
    Free(userContext->memory);
    Free(userContext);
    Enable_Interrupts();
}

/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
int Load_User_Program(char* exeFileData,
                      ulong_t exeFileLength,
                      struct Exe_Format* exeFormat,
                      const char* command,
                      struct User_Context** pUserContext) {
    /*
     * Hints:
     * - Determine where in memory each executable segment will be placed
     * - Determine size of argument block and where it memory it will
     *   be placed
     * - Copy each executable segment into memory
     * - Format argument block in memory
     * - In the created User_Context object, set code entry point
     *   address, argument block address, and initial kernel stack pointer
     *   address
     */
    // TODO("Load a user executable into a user memory space using
    // segmentation");
    // project2 Load_User_Program
    unsigned int i;
    struct User_Context* userContext = NULL;

    /* 要分配的最大内存空间 */
    ulong_t maxVirtualAddr = 0;
    /* 计算用户态进程所需的最大内存空间 */
    // 计算出每一个段的最大地址处，然后选出最大的地址，作为要分配多少内存
    for (i = 0; i < exeFormat->numSegments; i++) {
        struct Exe_Segment* segment = &exeFormat->segmentList[i];
        // startAddress
        // 为此段在进程空间（给每一个进程划分的内存）中的起始位置
        // sizeInMemory 为此段的在内存中的大小
        // 两者加起来就是的最大地址处
        ulong_t addr = segment->startAddress + segment->sizeInMemory;
        if (addr > maxVirtualAddr)
            maxVirtualAddr = addr;
    }

    /* 程序参数数目 */
    unsigned int numArgs;
    /* 获取参数块的大小 */
    ulong_t argBlockSize;
    Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
	// Round_Up_To_Page 函数可以将一个地址转换为可以整除一个页大小的地址（比源地址大）
	// 进程空间： 所有的段 + 进程堆栈 + 参数块 p163
    ulong_t size = Round_Up_To_Page(maxVirtualAddr) + DEFAULT_USER_STACK_SIZE;
    /* 参数块地址 */
    ulong_t argBlockAddr = size;
    size += argBlockSize;

    /* 按相应大小创建一个进程 */
    userContext = Create_User_Context(size);
    /* 如果进程创建失败则返回错误信息 */
    if (userContext == NULL) {
        return -1;
    }

    /* 将 ELF 文件中的各段内容复制到分配的用户内存空间（userContext->memory） */
    for (i = 0; i < exeFormat->numSegments; i++) {
        struct Exe_Segment* segment = &exeFormat->segmentList[i];
        memcpy(
			// memory 是进程空间的起始地址，startAddress 是一个段的在进程空间的起始地址，两者加起来就是一个段的在系统内存中的地址
			userContext->memory + segment->startAddress, 
			// exeFileData 是 ELF 文件的缓冲区，offsetInFile 是一个段在 ELF 文件中的位置，两者加起来就是一个段的在缓冲区的位置
            exeFileData + segment->offsetInFile, 
			segment->lengthInFile
		);
    }

    /* 格式化参数块，构造参数块数据结构 */
    Format_Argument_Block(userContext->memory + argBlockAddr, numArgs,
                          argBlockAddr, command);

    /* 初始化数据段、堆栈段及代码段信息 */
    userContext->entryAddr = exeFormat->entryAddr;
    userContext->argBlockAddr = argBlockAddr;
    // 参数块在进程堆栈之后，堆栈是从高地址向低地址生长的，所以要用参数块的起始地址
    userContext->stackPointerAddr = argBlockAddr;  

    /* 将初始化完毕的 User_Context 赋给*pUserContext */
    *pUserContext = userContext;

    return 0;
}

/*
 * Copy data from user memory into a kernel buffer.
 * Params:
 * destInKernel - address of kernel buffer
 * srcInUser - address of user buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize) {
    /*
     * Hints:
     * - the User_Context of the current process can be found
     *   from g_currentThread->userContext
     * - the user address is an index relative to the chunk
     *   of memory you allocated for it
     * - make sure the user buffer lies entirely in memory belonging
     *   to the process
     */
    // TODO("Copy memory from user buffer to kernel buffer");
    // project2 Copy_From_User
    struct User_Context* userContext = g_currentThread->userContext;
    /* 如果访问的用户内存空间非法(越界访问)，则直接返回失败 */
    if (!Validate_User_Memory(userContext, srcInUser, bufSize))
        return false;
    /* 拷贝当前用户内存空间数据到系统内核空间 */
    memcpy(destInKernel, userContext->memory + srcInUser, bufSize);
    /* 拷贝成功则返回 1 */
    return true;
}

/*
 * Copy data from kernel memory into a user buffer.
 * Params:
 * destInUser - address of user buffer
 * srcInKernel - address of kernel buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize) {
    /*
     * Hints: same as for Copy_From_User()
     */
    // TODO("Copy memory from kernel buffer to user buffer");
    // project2 Copy_To_User
    struct User_Context* userContext = g_currentThread->userContext;
    /* 如果需要拷贝的内容超出用户内存空间(越界)，则直接返回失败 */
    if (!Validate_User_Memory(userContext, destInUser, bufSize))
        return false;
    /* 拷贝当前系统内核空间数据到用户内存空间 */
    memcpy(userContext->memory + destInUser, srcInKernel, bufSize);
    /* 拷贝成功则返回 1 */
    return true;
}

/*
 * Switch to user address space belonging to given
 * User_Context object.
 * Params:
 * userContext - the User_Context
 */
void Switch_To_Address_Space(struct User_Context* userContext) {
    /*
     * Hint: you will need to use the lldt assembly language instruction
     * to load the process's LDT by specifying its LDT selector.
     */
    // TODO("Switch to user address space using segmentation/LDT");
    // project2 Switch_To_Address_Space
    /* 切换到新的局部描述符表(LDT) */
    ushort_t ldtSelector = userContext->ldtSelector;
    __asm__ __volatile__("lldt %0" : : "a"(ldtSelector));
}
