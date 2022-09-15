/*
 * ELF executable loading
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003, David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.29 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/errno.h>
#include <geekos/kassert.h>
#include <geekos/ktypes.h>
#include <geekos/screen.h>  /* for debug Print() statements */
#include <geekos/pfat.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/elf.h>

/**
 * From the data of an ELF executable, determine how its segments
 * need to be loaded into memory.
 * @param exeFileData buffer containing the executable file
 * @param exeFileLength length of the executable file in bytes
 * @param exeFormat structure describing the executable's segments
 *   and entry address; to be filled in
 * @return 0 if successful, < 0 on error
 */
int Parse_ELF_Executable(char* exeFileData,
                         ulong_t exeFileLength,
                         struct Exe_Format* exeFormat) {
    // TODO("Parse an ELF executable image");
    elfHeader* ELFHeader = (elfHeader*)exeFileData;
    
    // 段的个数
    exeFormat->numSegments = ELFHeader->phnum;
    Print("Num Segments: %d", exeFormat->numSegments);
    // 代码入口地址
    exeFormat->entryAddr = ELFHeader->entry;
    Print("Code Entry Addr: %x", exeFormat->entryAddr);
    // 获取头部表在文件中的位置，便于读取信息
    programHeader* programHeaderTableAddr =
        (programHeader*)(exeFileData + ELFHeader->phoff);
    // 填充Exe_Segment
    unsigned int i;
    for (i = 0; i < exeFormat->numSegments; i++, programHeaderTableAddr++) {
        struct Exe_Segment* segment = &exeFormat->segmentList[i];
        // 获取该段在文件中的偏移量*
        segment->offsetInFile = programHeaderTableAddr->offset;
        // 获取该段的数据在文件中的长度
        segment->lengthInFile = programHeaderTableAddr->fileSize;
        // 获取该段在用户内存中的起始地址
        segment->startAddress = programHeaderTableAddr->vaddr;
        Print("Start address of segment in user memory: %x", programHeaderTableAddr->vaddr);
        // 获取该段在内存中的大小
        segment->sizeInMemory = programHeaderTableAddr->memSize;
        // 获取该段的保护标志位
        segment->protFlags = programHeaderTableAddr->flags;
    }
    return 0;

}
