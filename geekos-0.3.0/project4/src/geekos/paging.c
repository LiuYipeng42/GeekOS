/*
 * Paging (virtual memory) support
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.55 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/bitset.h>
#include <geekos/blockdev.h>
#include <geekos/crc32.h>
#include <geekos/errno.h>
#include <geekos/gdt.h>
#include <geekos/idt.h>
#include <geekos/int.h>
#include <geekos/kassert.h>
#include <geekos/kthread.h>
#include <geekos/malloc.h>
#include <geekos/mem.h>
#include <geekos/paging.h>
#include <geekos/screen.h>
#include <geekos/segment.h>
#include <geekos/string.h>
#include <geekos/user.h>
#include <geekos/vfs.h>

/* ----------------------------------------------------------------------
 * Public data
 * ---------------------------------------------------------------------- */
pde_t* g_kernel_pde;
static void* Bitmap;
static struct Paging_Device* pagingDevice;
static int numPagingDiskPages;
/* ----------------------------------------------------------------------
 * Private functions/data
 * ---------------------------------------------------------------------- */

#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)

#define WriteFault(args...) \
    if (1)   \
        Print(args)

void checkPaging() {
    unsigned long reg = 0;
    __asm__ __volatile__("movl %%cr0, %0" : "=a"(reg));
    Print("Paging on ? : %d\n", (reg & (1 << 31)) != 0);
}

/*
 * Print diagnostic information for a page fault.
 */
static void Print_Fault_Info(uint_t address, faultcode_t faultCode) {
    extern uint_t g_freePageCount;

    Print("Pid %d, Page Fault received, at address %x (%d pages free)\n",
          g_currentThread->pid, address, g_freePageCount);
    if (faultCode.protectionViolation)
        Print("   Protection Violation, ");
    else
        Print("   Non-present page, ");
    if (faultCode.writeFault)
        Print("Write Fault, ");
    else
        Print("Read Fault, ");
    if (faultCode.userModeFault)
        Print("in User Mode\n");
    else
        Print("in Supervisor Mode\n");
}

/*
 * Handler for page faults.
 * You should call the Install_Interrupt_Handler() function to
 * register this function as the handler for interrupt 14.
 */
/*static*/ void Page_Fault_Handler(struct Interrupt_State* state) {
    // project4 Page_Fault_Handler
    ulong_t address;
    faultcode_t faultCode;

    KASSERT(!Interrupts_Enabled());

    /* Get the address that caused the page fault */
    address = Get_Page_Fault_Address();
    // Print("Page fault @%lx\n", address);

    /* Get the fault code */
    faultCode = *((faultcode_t*)&(state->errorCode));

    // /* user faults just kill the process */
    struct User_Context* userContext = g_currentThread->userContext;

    //写错误，缺页情况为堆栈生长到新页
    if (faultCode.writeFault) {
        WriteFault("write Fault\n");
        int res;
        if (!Alloc_User_Page(userContext->pageDir, Round_Down_To_Page(address),
                             PAGE_SIZE)) {
            Print("Alloc_User_Page error in Page_Fault_Handler\n");
            Exit(-1);
        }
        return;
    } else {
        //读错误，分两种缺页情况
        Print("read fault\n");
        //先找到虚拟地址对应的页表项
        ulong_t pdeIndex = PAGE_DIRECTORY_INDEX(address);
        ulong_t pteIndex = (address << 10) >> 22;
        pde_t* pdeItemAddr = (pde_t*)userContext->pageDir + pdeIndex;
        pte_t* pteItemAddr = NULL;

        // 目标 pde 表项不存在
        if (pdeItemAddr->present) {
            pteItemAddr = (pte_t*)((pdeItemAddr->pageTableBaseAddr) << 12);
            pteItemAddr += pteIndex;
        } else {
            // 非法地址访问的缺页情况
            Print_Fault_Info(address, faultCode);
            Exit(-1);
        }

        // 内存和磁盘中都不存在目标页表
        if (pteItemAddr->kernelInfo != KINFO_PAGE_ON_DISK) {
            // 非法地址访问的缺页情况
            Print_Fault_Info(address, faultCode);
            Exit(-1);
        }

        // 因为页保存在磁盘pagefile引起的缺页
        int pagefileIndex = pteItemAddr->pageBaseAddr;
        void* paddr =
            Alloc_Pageable_Page(pteItemAddr, Round_Down_To_Page(address));
        if (paddr == NULL) {
            Print("no more page/n");
            Exit(-1);
        }

        *((uint_t*)pteItemAddr) = 0;
        pteItemAddr->present = 1;
        pteItemAddr->flags = VM_WRITE | VM_READ | VM_USER;
        pteItemAddr->globalPage = 0;
        pteItemAddr->pageBaseAddr = PAGE_ALLIGNED_ADDR(paddr);

        //从页面文件中把页读到内存中
        Enable_Interrupts();
        struct Page* page = Get_Page((ulong_t)paddr);
        page->flags &= ~(PAGE_PAGEABLE);
        page->flags |= PAGE_LOCKED;
        Read_From_Paging_File(paddr, Round_Down_To_Page(address),
                              pagefileIndex);
        page->flags &= ~(PAGE_LOCKED);
        page->flags |= PAGE_PAGEABLE;
        Disable_Interrupts();
        // 释放页面文件中的空间
        Free_Space_On_Paging_File(pagefileIndex);
        return;
    }
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Initialize virtual memory by building page tables
 * for the kernel and physical memory.
 */
void Init_VM(struct Boot_Info* bootInfo) {
    /*
     * Hints:
     * - Build kernel page directory and page tables
     * - Call Enable_Paging() with the kernel page directory
     * - Install an interrupt handler for interrupt 14,
     *   page fault
     * - Do not map a page at address 0; this will help trap
     *   null pointer references
     */
    // project4 Init_VM
    // ("Build initial kernel page directory and page tables");
    int kernelPdeItemNum;
    int AllPageCount;
    int i, j;
    uint_t pageNum;
    pte_t* pteCur;

    // 计算物理内存的页数，页的大小为 4 KB
    AllPageCount = bootInfo->memSizeKB / 4;
	Print("Page num: %d\n", AllPageCount);

    // 计算内核页目录中要多少个目录项，才能完全映射所有的物理内存页。
    // NUM_PAGE_TABLE_ENTRIES 是一个页表有几个表项，
    // 表达式右侧计算的是需要分配多少个页表，因为一个页目录表的表项对应一个页表
    // 所以页表数就是目录项数
    kernelPdeItemNum = AllPageCount / NUM_PAGE_TABLE_ENTRIES +
                         (AllPageCount % NUM_PAGE_TABLE_ENTRIES == 0 ? 0 : 1);
    Print("pde Item Num: %d\n", kernelPdeItemNum);

    //为内核页目录分配一页空间
    g_kernel_pde = (pde_t*)Alloc_Page();
    KASSERT(g_kernel_pde != NULL);

    //将页中所有位清0
    memset(g_kernel_pde, 0, PAGE_SIZE);

    //初始化最后一个页目录表项和对应的页表。注意，页表中的页表项不一定足够1024个
    int lastPteNum;
    lastPteNum = AllPageCount % NUM_PAGE_TABLE_ENTRIES;
    //注意当lastPteNum=0时，意味着最后一个页目录项对应的页表是满的，就是说页表中1024个页表项都指向一个有效的页。
    if (lastPteNum == 0) {
        lastPteNum = NUM_PAGE_TABLE_ENTRIES;
    }

    pde_t* pdeCur;
    pdeCur = g_kernel_pde;
    pageNum = 0;
    int pteItemNum = NUM_PAGE_TABLE_ENTRIES;
    for (i = 0; i < kernelPdeItemNum; i++) {
        pdeCur->present = 1;
        pdeCur->flags = VM_WRITE | VM_READ | VM_EXEC;
        pdeCur->accesed = 0;  // 页表没有被访问过
        pdeCur->reserved = 0;
        pdeCur->largePages = 0;
        pdeCur->globalPage = 1;  // 内核中的 PDE 和 PTE 都是全局的
        pdeCur->kernelInfo = 0;

        pteCur = (pte_t*)Alloc_Page();
        KASSERT(pteCur != NULL);
        memset(pteCur, 0, PAGE_SIZE);
        pdeCur->pageTableBaseAddr = PAGE_ALLIGNED_ADDR(pteCur);

        if (i == kernelPdeItemNum - 1)
            pteItemNum = lastPteNum;

        // 初始化页表项
        for (j = 0; j < pteItemNum; j++) {
            pteCur->present = 1;
            pteCur->flags = VM_WRITE;
            pteCur->accesed = 0;  // 页没有被访问过
            pteCur->dirty = 0;    // 页中的数据没有被修改过
            pteCur->globalPage = 1;
			pteCur->kernelInfo = 0;
            pteCur->pageBaseAddr = pageNum;
            pteCur++;
            pageNum += 1;
        }
        pdeCur ++;
    }

    //从现在开始，系统的寻址必须进行分页机制转换
    Enable_Paging(g_kernel_pde);

	// 注册缺页中断处理函数
    Install_Interrupt_Handler(14, Page_Fault_Handler);

    // for (i = 0; i < 1024; i++) {
    //     if (g_kernel_pde[i].present == 1){
    //         Print("%d\n", i);
    //     }
    // }
}

/**
 * Initialize paging file data structures.
 * All filesystems should be mounted before this function
 * is called, to ensure that the paging file is available.
 */
void Init_Paging(void) {
    // project4 Init_Paging
    // ("Initialize paging file data structures");
    pagingDevice = Get_Paging_Device();  // 获取一个分页文件设备
    if (pagingDevice == NULL) {
        Print("can not find pagefile\n");
        return;
    }
	// pagingDevice->numSectors 是一个分页文件的扇区数，SECTORS_PER_PAGE是一个页的扇区数
	// 所以可以算出共有多少个磁盘上有多少页用于虚拟内存
    numPagingDiskPages = pagingDevice->numSectors / SECTORS_PER_PAGE;
    //为 pagefile 中每一页设置一个标识位，用于表示一个页是否被使用
    Bitmap = Create_Bit_Set(numPagingDiskPages);
}

/**
 * Find a free bit of disk on the paging file for this page.
 * Interrupts must be disabled.
 * @return index of free page sized chunk of disk space in
 *   the paging file, or -1 if the paging file is full
 */
int Find_Space_On_Paging_File(void) {
    KASSERT(!Interrupts_Enabled());
    // project4 Find_Space_On_Paging_File
    // ("Find free page in paging file");  
    return Find_First_Free_Bit(Bitmap, numPagingDiskPages);
}

/**
 * Free a page-sized chunk of disk space in the paging file.
 * Interrupts must be disabled.
 * @param pagefileIndex index of the chunk of disk space
 */
void Free_Space_On_Paging_File(int pagefileIndex) {
    KASSERT(!Interrupts_Enabled());
    // project4 Free_Space_On_Paging_File
    // ("Free page in paging file");
    KASSERT(0 <= pagefileIndex && pagefileIndex < numPagingDiskPages);
    Clear_Bit(Bitmap, pagefileIndex);
}

/**
 * Write the contents of given page to the indicated block 将内存中的页写入到分页文件中
 * of space in the paging file.
 * @param paddr a pointer to the physical memory of the page    要进行写入的页在内存中的地址
 * @param vaddr virtual address where page is mapped in user memory
 * @param pagefileIndex the index of the page sized chunk of space in the paging file  分页文件的页的索引
 */
void Write_To_Paging_File(void* paddr, ulong_t vaddr, int pagefileIndex) {
    struct Page* page = Get_Page((ulong_t)paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE)); /* Page must be locked! */
    // project4 Write_To_Paging_File
    // ("Write page data to paging file");
    
    int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        Block_Write(
			pagingDevice->dev,  // 指向要进行写入的设备，pagingDevice在 Init_Paging 函数中就已经被赋值
            pagefileIndex * SECTORS_PER_PAGE + (pagingDevice->startSector) + i, // 要进行写入的起始扇区
            paddr + i * SECTOR_SIZE // 要写入的内存数据在内存中的地址，一次写入一个扇区
		);
    }
    Set_Bit(Bitmap, pagefileIndex); // 对已写入的分页文件的页进行标记，表明已有数据

}

/**
 * Read the contents of the indicated block
 * of space in the paging file into the given page.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page will be re-mapped in
 *   user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
void Read_From_Paging_File(void* paddr, ulong_t vaddr, int pagefileIndex) {
    struct Page* page = Get_Page((ulong_t)paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE));  // Page must be locked!
    // ("Read page data from paging file");

	int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        Block_Read(pagingDevice->dev,
                   SECTORS_PER_PAGE * pagefileIndex + (pagingDevice->startSector) + i,
                   paddr + i * SECTOR_SIZE);
        //     Hex_Dump (paddr + i*SECTOR_SIZE, SECTOR_SIZE);
    }
}
