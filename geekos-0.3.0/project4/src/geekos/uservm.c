/*
 * Paging-based user mode implementation
 * Copyright (c) 2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.50 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */


#include <geekos/argblock.h>
#include <geekos/gdt.h>
#include <geekos/int.h>
#include <geekos/kthread.h>
#include <geekos/malloc.h>
#include <geekos/mem.h>
#include <geekos/paging.h>
#include <geekos/range.h>
#include <geekos/string.h>
#include <geekos/user.h>
#include <geekos/vfs.h>


#define Debug(args...) \
    if (1)             \
        Print(args)

/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */
/**
 * 展示内存
 */
void DisplayMemory(pde_t* pde, int start, int end) {
    int i;
    char binary[32];
    pte_t* pte = 0;
    Set_Current_Attr(ATTRIB(BLACK, AMBER | BRIGHT));
    Print("Page Directory\n");
    Set_Current_Attr(ATTRIB(BLACK, GRAY));
    Print("%10s\t%10s\n", "pde", "value");
    Print("%10x\t%10x\n", &pde[PAGE_DIRECTORY_INDEX(USER_VM_END)],
          pde[PAGE_DIRECTORY_INDEX(USER_VM_END)]);
    Set_Current_Attr(ATTRIB(BLACK, AMBER | BRIGHT));
    Print("Page Table\n");
    Set_Current_Attr(ATTRIB(BLACK, GRAY));
    Print("%10s\t%10s\t%10s\t%10s\t%10s\n", "idx", "pte addr", "pte value",
          "pf addr", "pf value");
    pte = pde[PAGE_DIRECTORY_INDEX(USER_VM_END)].pageTableBaseAddr << 12;
    for (i = start; i < end + 1; i++) {
        Print("%10d\t%10x\t%10x\t%10x\t%10x\n", i, &pte[i], pte[i],
              pte[i].pageBaseAddr << 12, *(int*)(pte[i].pageBaseAddr << 12));
    }
}

/**
 * 把线性地址转换为物理地址
 * 成功返回对应物理地址，失败返回NULL
 * pdeAddr: 项目录表起始地址
 * linearAddr: 用户进程空间中的一个地址（某一个页中的地址），页目录项地址 + 页表项 + 页内地址
 */
uint_t Lin_To_Phyaddr(pde_t* pdeAddr, uint_t linearAddr) {
    // project4 Lin_To_Phyaddr
    // 首先找到所在页的地址，最后加上页内地址即可
    uint_t pdeItemIndex = PAGE_DIRECTORY_INDEX(linearAddr);  // 获取在 pde 表中的索引
    uint_t pteItemIndex = PAGE_IDNEX(linearAddr);            // 获取在 pte 表中的索引
    uint_t offsetAddress = linearAddr & 0xfff;               // 页内地址

    pde_t* pdeItemAddr = pdeAddr + pdeItemIndex;
    pte_t* pteCur = 0;

    if (pdeItemAddr->present) {
        pteCur = (pte_t*) PAGE_ADDR(pdeItemAddr->pageTableBaseAddr); // 从页目录表项获取到页表的地址
        pteCur += pteItemIndex;    // 获取到对应的页表项
        if (pteCur->present == 0) {
            Print("the page do not present!\n");
            KASSERT(0);
        }
        return PAGE_ADDR(pteCur->pageBaseAddr) + offsetAddress;  // 加上页内地址后返回
    } else {
        Print("Trying to resolve non-existent address%u/n", linearAddr);
        return 0;
    }
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */
/*
 * 将存储在缓冲区中的段信息读入到线性地址对应的页中
 * 成功返回true,失败返回false
 */
bool Copy_User_Page(pde_t* desPdeAddr, // 数据复制的目标页目录表
                    uint_t desAddr,    // 数据复制的目的线性地址，
                    char* srcAddr,     // 要复制的数据的地址，内存中的真实的物理地址
                    uint_t dataSize) {
    // project4 Copy_User_Page
    uint_t phyAddr;
    uint_t firstPageDataSize;
    int pageNums;
    struct Page* page;

    //检测进程所需用户内存空间占用多少页面。pageNums==1,占用一页;pageNums==0,占用一页以上
    if (Round_Down_To_Page(desAddr + dataSize) == Round_Down_To_Page(desAddr)) {
        firstPageDataSize = dataSize;
        pageNums = 1;
    } else {
        firstPageDataSize = Round_Up_To_Page(desAddr) - desAddr;  // 计算出从目标地址到所在页面结尾的长度
        dataSize -= firstPageDataSize;  // 分配完第一个页面后，还剩下的数据长度
        pageNums = 0;
    }

    phyAddr = Lin_To_Phyaddr(desPdeAddr, desAddr);
    if (phyAddr == 0) {
        return false;
    }
    page = Get_Page(phyAddr);
    //保证在复制过程中，所用的的页不会因缺页中断被调换出去
    Disable_Interrupts();
    page->flags &= ~PAGE_PAGEABLE;
    Enable_Interrupts();
    //复制第一页内容
    memcpy((char*)phyAddr, srcAddr, firstPageDataSize);
    page->flags |= PAGE_PAGEABLE;

    if (pageNums == 1) {
        return true;
    }

    // 对于占用一页以上的情况，处理中间部分的页（此部分的所占用的页数可能为0）
	// desAddr 要等于这个值，是因为这部分空间已经被前面复制的数据所占用, 在数值上等于 Round_Up_To_Page(dest_user)
    desAddr += firstPageDataSize; 
	// firstPageDataSize 长度的数据已经被复制过，所以 srcAddr 要跳过这部分数据
    srcAddr += firstPageDataSize;  
	// 要复制的数据长度因为前面已经复制过一部分的数据，所以要减去这部分的长度
    dataSize -= firstPageDataSize;

	// 在复制第一页数据的时候，desAddr 就已经变成页大小的整数倍，每次增加的大小也是一个页的大小，
	// 当复制到最后一页时，dataSize 的大小小于一页，desAddr + dataSize 经过舍去后就和 desAddr 相等
    while (desAddr != Round_Down_To_Page(desAddr + dataSize)) {
        phyAddr = Lin_To_Phyaddr(desPdeAddr, desAddr);
        if (phyAddr == 0) {
            return false;
        }
        page = Get_Page(phyAddr);
        //保证在复制过程中，所用的的页不会因缺页中断被调换出去
        Disable_Interrupts();
        page->flags &= ~PAGE_PAGEABLE;
        Enable_Interrupts();

        memcpy((char*)phyAddr, srcAddr, PAGE_SIZE);
        page->flags |= PAGE_PAGEABLE;

        desAddr += PAGE_SIZE;
        dataSize -= PAGE_SIZE;
        srcAddr += PAGE_SIZE;
    }

    //处理最后一页
    phyAddr = Lin_To_Phyaddr(desPdeAddr, desAddr);
    if (phyAddr == 0) {
        return false;
    }
    //保证在复制过程中，所用的的页不会因缺页中断被调换出去
    Disable_Interrupts();
    page->flags &= ~PAGE_PAGEABLE;
    Enable_Interrupts();

    memcpy((char*)phyAddr, srcAddr, dataSize);
    page->flags |= PAGE_PAGEABLE;
    return true;
}

/*
 * 根据传入的 PDE 创建对应的页目录项及其页表
 * 失败返回false，成功返回true
 *  pdeAddr：pde的第一项的的地址
 *  startAddress：数据应该存放的目的线性地址
 *  sizeInMemory：要存放的数据大小
 */
bool Alloc_User_Page(pde_t* pdeAddr, uint_t startAddress, uint_t sizeInMemory) {
    // project4 Alloc_User_Page

    uint_t pdeIndex = PAGE_DIRECTORY_INDEX(startAddress);
    uint_t pteIndex = PAGE_IDNEX(startAddress);

    pde_t* pdeItemAddr = pdeAddr + pdeIndex;
    pte_t* pteCur;

    Debug("pde index: %d, ", pdeIndex);
    Debug("pde item addr=%x, ", pdeItemAddr); 

    // 建立startAddress对应的页目录表项与页表
    // 在 pdeItemAddr 指向的地址上建立一个页目录项
    // 目标页目录项已经存在
    if (pdeItemAddr->present) {
        pteCur = (pte_t*)PAGE_ADDR(pdeItemAddr->pageTableBaseAddr);
        Debug("existed pde item\n");
    } else {
        // 页目录表项没有建立
        // 分配一个页表
        pteCur = (pte_t*)Alloc_Page();
        if (pteCur == NULL) {
            Debug("can not allocate page in Alloc_User_Page\n");
            return false;
        }
        memset(pteCur, 0, PAGE_SIZE);
        // 设置对应的页目录表项
        *((uint_t*)pdeItemAddr) = 0;
        pdeItemAddr->present = 1;
        pdeItemAddr->flags = VM_WRITE | VM_READ | VM_USER;
        pdeItemAddr->globalPage = 0;
        pdeItemAddr->pageTableBaseAddr = PAGE_TABLE_INDEX(pteCur);

        Debug("new pde item\n");
    }

    // 找到页表中对应于startAddress的页表项
    pteCur += pteIndex;

    // 建立startAddress对应的页表项与页
    int pageNum;
    void* pageAddr;
    pageNum =
        Round_Up_To_Page(startAddress - Round_Down_To_Page(startAddress) + sizeInMemory) / PAGE_SIZE;
		// startAddress - Round_Down_To_Page(startAddress) 是不能整除一个页大小的多出的部分，
		// 这部分加上 sizeInMemory 才是应该分配的内存大小，然后再利用 Round_Up_To_Page 函数向上取整
		// 获得应该分配的内存大小
 
    int i;
    for (i = 0; i < pageNum; i++) {
        // 对应的页表项没有建立的情况（此时意味着对应的页没有建立）
        Debug("pte index: %d, ", pteIndex + i);
        Debug("pte item addr=%x\n", pteCur);
        if (!pteCur->present) {
            pageAddr = Alloc_Pageable_Page(pteCur, Round_Down_To_Page(startAddress));
            if (pageAddr == NULL) {
                Debug("can not allocate page in Alloc_User_Page\n");
                return false;
            }
            // 设置页表项
            *((uint_t*)pteCur) = 0;
            pteCur->present = 1;
            pteCur->flags = VM_WRITE | VM_READ | VM_USER;
            pteCur->globalPage = 0;
            pteCur->pageBaseAddr = PAGE_ALLIGNED_ADDR(pageAddr);
            KASSERT(pageAddr != 0);
            Debug("new pte item: physical addr=%x liner addr=%x\n", pageAddr, startAddress);
        }
        pteCur++;
        startAddress += PAGE_SIZE;
    }

    Debug("existed pde item index: ");
    for (i = 0; i < 1024; i++) {
        if (pdeAddr[i].present == 1){
            Debug("%d ", i);
        }
    }
    Debug("\n");
    Debug("\n");

    return true;
}

/**
 * 创建一个在分页模式下使用的User_Context
 */
struct User_Context* Create_User_Context() {
    // project4 Create_User_Context
    struct User_Context* userContext;
    userContext = (struct User_Context*)Malloc(sizeof(struct User_Context));
    if (userContext == NULL) {
        Print("malloc User_Context fail in Create_User_Context/n");
        return NULL;
    }
    userContext->ldtDescriptor = NULL;
    userContext->memory = NULL;
    userContext->size = 0;
    userContext->ldtSelector = 0;
    userContext->csSelector = 0;
    userContext->dsSelector = 0;

    userContext->pageDir = NULL;
    userContext->entryAddr = 0;
    userContext->argBlockAddr = 0;
    userContext->stackPointerAddr = 0;
    userContext->refCount = 0;

    // UserContext中涉及分段机制的选择子,描述符
    userContext->ldtDescriptor = Allocate_Segment_Descriptor();
    if (userContext->ldtDescriptor == NULL) {
        Print("allocate segment descriptor fail\n");
        return -1;
    }
    Init_LDT_Descriptor(userContext->ldtDescriptor, userContext->ldt,
                        NUM_USER_LDT_ENTRIES);
    userContext->ldtSelector =
        Selector(USER_PRIVILEGE, true,
                 Get_Descriptor_Index(userContext->ldtDescriptor));

    //注意，在GeekOS的分页机制下，用户地址空间默认从线性地址2G开始
    Init_Code_Segment_Descriptor(&userContext->ldt[0], USER_VM_START,
                                 USER_VM_LEN / PAGE_SIZE, USER_PRIVILEGE);
    Init_Data_Segment_Descriptor(&userContext->ldt[1], USER_VM_START,
                                 USER_VM_LEN / PAGE_SIZE, USER_PRIVILEGE);

    userContext->csSelector = Selector(USER_PRIVILEGE, false, 0);
    userContext->dsSelector = Selector(USER_PRIVILEGE, false, 1);

    return userContext;
}

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* context) {
    /*
     * Hints:
     * - Free all pages, page tables, and page directory for
     *   the process (interrupts must be disabled while you do this,
     *   otherwise those pages could be stolen by other processes)
     * - Free semaphores, files, and other resources used
     *   by the process
     */
    // project4 Destroy_User_Context
    // ("Destroy User_Context data structure after process exits");
    if (context == NULL) {
        return;
    }

    Free_Segment_Descriptor(context->ldtDescriptor);
    Set_PDBR(g_kernel_pde);  // Page Directory Base Register
    if (context->pageDir != NULL) {
        pde_t* pdeAddr = context->pageDir;
        // KASSERT(!Interrupts_Enabled());
        // Enable_Interrupts();
        bool flag;
        flag = Begin_Int_Atomic();

        pde_t* pdeCur;
        if (pdeAddr == NULL) {
            return true;
        }
        for (pdeCur = pdeAddr; pdeCur < pdeAddr + NUM_PAGE_DIR_ENTRIES; pdeCur++) {
            pte_t* pteCur;
            pte_t* pteAddr;
            if (!pdeCur->present) {
                continue;
            }
            pteAddr = (pte_t*)(pdeCur->pageTableBaseAddr << 12);
            for (pteCur = pteAddr; pteCur < pteAddr + NUM_PAGE_TABLE_ENTRIES; pteCur++) {
                if (pteCur->present) {
                    Free_Page((void*)(pteCur->pageBaseAddr << 12));
                } else if (pteCur->kernelInfo == KINFO_PAGE_ON_DISK) {
                    //当页在pagefile上时，pte_t结构中的pageBaseAddr指示了页在pagefile中的位置
                    Free_Space_On_Paging_File(pteCur->pageBaseAddr);
				}
				Free_Page(pteAddr);
			}
			// Disable_Interrupts();
			Free_Page(pdeAddr);

			End_Int_Atomic(flag);
		}
		context->pageDir = 0;
		Free(context);
	}
}


/*
 * Copy data from user buffer into kernel buffer.
 * Returns true if successful, false otherwise.
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t numBytes) {
    /*
     * Hints:
     * - Make sure that user page is part of a valid region
     *   of memory
     * - Remember that you need to add 0x80000000 to user addresses
     *   to convert them to kernel addresses, because of how the
     *   user code and data segments are defined
     * - User pages may need to be paged in from disk before being accessed.
     * - Before you touch (read or write) any data in a user
     *   page, **disable the PAGE_PAGEABLE bit**.
     *
     * Be very careful with race conditions in reading a page from disk.
     * Kernel code must always assume that if the struct Page for
     * a page of memory has the PAGE_PAGEABLE bit set,
     * IT CAN BE STOLEN AT ANY TIME.  The only exception is if
     * interrupts are disabled; because no other process can run,
     * the page is guaranteed not to be stolen.
     */
    // project4 Copy_From_User
    // ("Copy user data to kernel buffer");
    struct User_Context* userContext = g_currentThread->userContext;
    void* phyAddr = (void*)(USER_VM_START) + srcInUser;

    if ((srcInUser + numBytes) < userContext->size) {
        memcpy(destInKernel, phyAddr, numBytes);
        return true;
    }
    return false;
}

/*
 * Copy data from kernel buffer into user buffer.
 * Returns true if successful, false otherwise.
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t numBytes) {
    /*
     * Hints:
     * - Same as for Copy_From_User()
     * - Also, make sure the memory is mapped into the user
     *   address space with write permission enabled
     */
    // project4 Copy_To_User
    // ("Copy kernel data to user buffer");
    struct User_Context* userContext = g_currentThread->userContext;
    void* phyAddr = (void*)(USER_VM_START) + destInUser;
    if ((destInUser + numBytes) < userContext->size) {
        memcpy(phyAddr, srcInKernel, numBytes);
        return true;
    }
    return false;
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
     * - This will be similar to the same function in userseg.c
     * - Determine space requirements for code, data, argument block,
     *   and stack
     * - Allocate pages for above, map them into user address
     *   space (allocating page directory and page tables as needed)
     * - Fill in initial stack pointer, argument block address,
     *   and code entry point fields in User_Context
     */
    // project4 Load_User_Program
    // ("Load user program into address space");
    struct User_Context* uContext;
    uContext = Create_User_Context();  //创建一个UserContext

    //处理分页涉及的数据
    pde_t* pageDirectoryEntry;
    pageDirectoryEntry = (pde_t*)Alloc_Page();
    if (pageDirectoryEntry == NULL) {
        Print("no more page!\n");
        return -1;
    }
    memset(pageDirectoryEntry, 0, PAGE_SIZE);
    // 将内核页目录复制到用户态进程的页目录中
    memcpy(pageDirectoryEntry, g_kernel_pde, PAGE_SIZE);
    // 将用户态进程对应高2G线性地址的页目录表项置为0，用户态进程中高2G的线性地址在GeekOS中为用户空间
    // 一张页目录表有 1024 个表项，对应 1024 个页表，一个页表有 1024 个表项，对应 1024 个页
    // 因为每一个页的大小是 4kb，所以 1024 * 1024 * 4kb 为 4G
    // 因为要将高2G线性地址的页目录表项置为 0，512个表项正好可以表达 2G 的内存，所以要用pageDirectoryEntry + 512，
    // 又因为一张页目录表的大小是一个页的大小，所以清零一般的页目录项的大小就是 PAGE_SIZE / 2
    memset(pageDirectoryEntry + 512, 0, PAGE_SIZE / 2);

    uContext->pageDir = pageDirectoryEntry;

    int i;
    int res;
    uint_t startAddress = 0;
    uint_t sizeInMemory = 0;
    uint_t offsetInFile = 0;
    uint_t lengthInFile = 0;
    for (i = 0; i < exeFormat->numSegments - 1; i++) {
        startAddress = exeFormat->segmentList[i].startAddress;
        sizeInMemory = exeFormat->segmentList[i].sizeInMemory;

        offsetInFile = exeFormat->segmentList[i].offsetInFile;
        lengthInFile = exeFormat->segmentList[i].lengthInFile;
        if (!sizeInMemory && !lengthInFile) {
            sizeInMemory = DEFAULT_STACK_SIZE;
            lengthInFile = DEFAULT_STACK_SIZE;
        }

        if (startAddress + sizeInMemory < USER_VM_LEN) {
            // 给数据段和代码段分配空间
            // 在GeekOS的分页机制下，用户地址空间默认从线性地址2G开始
            if (!Alloc_User_Page(pageDirectoryEntry, startAddress + USER_VM_START,
                                 sizeInMemory) ||
                !Copy_User_Page(pageDirectoryEntry, startAddress + USER_VM_START,
                                exeFileData + offsetInFile, lengthInFile)) {
                return -1;
            }
        } else {
            Print("startAddress+sizeInMemory > 2GB in Load_User_Program\n");
            return -1;
        }
    }

    // 处理参数块
    uint_t argsNum;
    uint_t stackAddr;
    uint_t argAddr;
    ulong_t argSize;
    Get_Argument_Block_Size(command, &argsNum, &argSize);
    if (argSize > PAGE_SIZE) {
        Print("Argument Block too big for one PAGE_SIZE\n");
        return -1;
    }

    // 给参数块在地址空间的尾部分配一页
    argAddr = Round_Down_To_Page(USER_VM_LEN - argSize);
    char* block_buffer = Malloc(argSize);
    KASSERT(block_buffer != NULL);
    Format_Argument_Block(block_buffer, argsNum, argAddr, command);

    if (!Alloc_User_Page(pageDirectoryEntry, argAddr + USER_VM_START, argSize) ||
        !Copy_User_Page(pageDirectoryEntry, argAddr + USER_VM_START, block_buffer,
                        argSize)) {
        return -1;
    }
    Free(block_buffer);

    //  在地址空间的尾部给堆栈分配一页
    stackAddr = USER_VM_LEN - Round_Up_To_Page(argSize) - DEFAULT_STACK_SIZE;
    if (!Alloc_User_Page(pageDirectoryEntry, stackAddr + USER_VM_START,
                         DEFAULT_STACK_SIZE)) {
        return -1;
    }

    // 栈帧是从地址大的地方生长到地址小的地方，所以堆栈的起始地址是刚才分配的页的最后的地址
    uint_t stack_start_addr = Round_Up_To_Page(stackAddr) + DEFAULT_STACK_SIZE;
    
    // 填充UserContext
    uContext->entryAddr = exeFormat->entryAddr;
    uContext->argBlockAddr = argAddr;
    uContext->size = USER_VM_LEN;
    uContext->stackPointerAddr = stack_start_addr;
    *pUserContext = uContext;

    // DisplayMemory(pageDirectoryEntry);
    return 0;
}

/*
 * Switch to user address space.
 */
void Switch_To_Address_Space(struct User_Context* userContext) {
    /*
     * - If you are still using an LDT to define your user code and data
     *   segments, switch to the process's LDT
     * -
     */
    // project4 Switch_To_Address_Space
    // ("Switch_To_Address_Space() using paging");
    if (userContext == 0) {
        Print("the userContext is NULL!/n");
        return;
    }
    Load_LDTR(userContext->ldtSelector); // 设置 LDT 寄存器 
    Set_PDBR(userContext->pageDir);
}
