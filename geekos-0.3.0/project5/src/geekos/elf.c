/*
 * ELF executable loading
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003, David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.29 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/elf.h>
#include <geekos/errno.h>
#include <geekos/fileio.h>
#include <geekos/kassert.h>
#include <geekos/ktypes.h>
#include <geekos/malloc.h>
#include <geekos/pfat.h>
#include <geekos/screen.h> /* for debug Print() statements */
#include <geekos/string.h>
#include <geekos/user.h>

#ifdef DEBUG
#ifndef ELF_DEBUG
#define ELF_DEBUG
#endif
#endif

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

    elfHeader* exeHeader = (elfHeader*)exeFileData;
    programHeader* progHeader;
    unsigned char elfMagic[] = {0x7F, 'E', 'L',
                                'F'};  // Magic sould look like that
    unsigned int programHeaderOffset, programHeaderEntrySize,
        programHeaderNumEntries;
    int i;

    // Checking ELF-Magic
    // KASSERT(strncmp((char*) elfMagic, (char*) exeHeader->ident, 4));
    if (strncmp((char*)elfMagic, (char*)exeHeader->ident, 4)) {
        return ENOEXEC;
    }

    // ony executables currently supported
    if (exeHeader->type != ET_EXEC)
        TODO("currently only Elf-executables are supported\n");
    if (exeHeader->machine != EM_386)
        TODO("currently only Intel architecture supported\n");

    exeFormat->entryAddr = exeHeader->entry;
    programHeaderOffset = exeHeader->phoff;
    programHeaderEntrySize = exeHeader->phentsize;
    programHeaderNumEntries = exeHeader->phnum;
    exeFormat->numSegments = programHeaderNumEntries;

    // loop over program heads to fetch segment information
    for (i = 0; i < programHeaderNumEntries; i++) {
        // read program header
        progHeader = (programHeader*)(exeFileData + programHeaderOffset +
                                      (i * programHeaderEntrySize));

        exeFormat->segmentList[i].offsetInFile = progHeader->offset;
        exeFormat->segmentList[i].lengthInFile = progHeader->fileSize;
        exeFormat->segmentList[i].startAddress = progHeader->vaddr;
        exeFormat->segmentList[i].sizeInMemory = progHeader->memSize;
        exeFormat->segmentList[i].protFlags = progHeader->flags;
    }
    return 0;
}
