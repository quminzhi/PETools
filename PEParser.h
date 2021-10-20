// PEParser.h: interface for the PEParser class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEPARSER_H__3830F7A5_92F4_4DFF_B42D_9B22DE362E64__INCLUDED_)
#define AFX_PEPARSER_H__3830F7A5_92F4_4DFF_B42D_9B22DE362E64__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define DIRECTORY_OFFSET 96

#include "Global.h"
#include "PEReader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PEParser:
//     The function will parse members of PE headers.
// @filebase: the base address of file buffer.
STATUS PEParser(IN PMEMORYBASE filebase);

// printHeaders:
//     printHeaders will print DosHeader, FileHeader, and OptionalHeader.
void printHeaders();

// printExportDirectory:
//     The function will print export directory, address table, name pointer table, and name ordinal table.
void printExportDirectory();

// printBaseRelocationDirectory:
//     The function will print each base relocation block.
void printBaseRelocationDirectory();

// printImportDirectory:
//     The function will print export directory, import lookup table, import address table, and name table.
void printImportDirectory();

// printBoundImportDirectory:
//     The function will print bound import descriptors and forwarder references.
void printBoundImportDirectory();


// TEST functions:

// TEST_PrintImportDirectoryTable():
//     This function will test the print of import directory table.
void TEST_PrintImportDirectoryTable();

// TEST_PrintBoundImportDirectory():
//     This function will test the print of bound import directory table.
void TEST_PrintBoundImportDirectory();

#endif // !defined(AFX_PEPARSER_H__3830F7A5_92F4_4DFF_B42D_9B22DE362E64__INCLUDED_)
