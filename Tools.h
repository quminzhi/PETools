// Tools.h: interface for the Tools class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TOOLS_H__05760431_89F6_4867_9765_8E2F9A55A832__INCLUDED_)
#define AFX_TOOLS_H__05760431_89F6_4867_9765_8E2F9A55A832__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "PEParser.h"
#include "PEReader.h"

///////////////////////////
// Tool Functions:
///////////////////////////

// FileBufferToImageBuffer:
//     The function will stretch a file buffer to an image buffer.
// @fileBuffer: the base address of file buffer.
// @imageBuffer: the base address of image buffer.
STATUS FileBufferToImageBuffer(IN PMEMORYBASE fileBuffer, OUT PMEMORYBASE* imageBuffer);

// ImageBufferToFileBuffer:
//     The function will pack an image buffer as a file buffer
// @imageBuffer: the base address of image buffer.
// @fileBuffer: the base address of file buffer.
STATUS ImageBufferToFileBuffer(IN PMEMORYBASE imageBuffer, OUT PMEMORYBASE* fileBuffer);

// AddSectionToBuffer:
//     The function will add a new section to file buffer
// @fileBuffer: the base address of file buffer.
// @newSection: a pointer to a struct of section header.
// @newFileBuffer: the base address of new file buffer where a new section is added.
STATUS AddSectionToBuffer(IN PMEMORYBASE fileBuffer, IN IMAGE_SECTION_HEADER* newSection, OUT PMEMORYBASE* newFileBuffer);

// ExtensionOfLastSection:
//     The function will extend the size of last section
// @fileBuffer: the base address of file buffer.
// @addition: the size to be extended.
// @newFileBuffer: the base address of new file buffer whose last section is extended.
STATUS ExtensionOfLastSection(IN PMEMORYBASE fileBuffer, IN DWORD addition, OUT PMEMORYBASE* newFileBuffer);

// MergingSections:
//     The function will merge all sections into the first one
// @fileBuffer: the base address of file buffer.
// @newFileBuffer: the base address of new file buffer whose sections are merged.
STATUS MergingSections(IN PMEMORYBASE fileBuffer, OUT PMEMORYBASE* newFileBuffer);

// SaveBufferAsFile:
//     The function will save memory data in a file.
// @filename: the name of file to save, in general it is an empty file.
// @buffer: the base address of memory buffer.
// @filesize: the size of the file.
STATUS SaveBufferAsFile(IN char* filename, IN PMEMORYBASE buffer);

// searchExportNamePointerTable:
//     The helper function for SearchFuncAddrByName, which will return the index of matching element in export name pointer table.
// @name: the name of function to be searched.
size_t searchExportNamePointerTable(char* name);

// SearchFuncAddrByName:
//     The function will search function address in image by function name.
// @buffer: the base address of memory buffer.
// @name: function name.
DWORD SearchFuncAddrByName(IN PMEMORYBASE buffer, char* name);

// searchNameOrdinalTable:
//     The function will search ordinal in name ordinal table, and return the index of matched element.
// @ordinal: the ordinal of function, NOT biased ordinal.
size_t searchNameOrdinalTable(WORD ordinal);

// SearchFuncAddrByOrdinal:
//     The function will search function address in image by biased ordinal.
// @buffer: the base address of memory buffer.
// @biasedOrdinal: function ordinal defined in .def file.
DWORD SearchFuncAddrByOrdinal(IN PMEMORYBASE buffer, WORD biasedOrdinal);

// MoveExportDirectoryToNewAddress:
//     The function will move export directory from .edata to a given address.
// @location: the location where export directory is going to be put.
// @buffer: the buffer that is going to be operated.
// @Return: the total size of moved elements in byte.
STATUS MoveExportDirectoryToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer);

// MoveBaseRelocationTableToNewAddress:
//     The function will move base relocation table from .rdata to a given address.
// @location: the location where to put base relocation table.
// @buffer: the buffer to be operated.
// @Return: the total size of moved elements in byte.
STATUS MoveBaseRelocationTableToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer);

// MoveImportDirectoryToNewAddress:
//     The function will move base relocation table to a given address.
// @location: the location where to put import directory, which is a foa.
// @buffer: the buffer to be operated.
// Assume that there are 3000h memory space available.
STATUS MoveImportDirectoryToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer);

// AddNewImportDirectory:
//     The function will add a new import directory to a given address.
// Notice that before running the function, we'd better to move import directory to a safe place so that
// there is enough space for new import directory.
// @location: the location where to insert import directory, which is a foa. The location must before end flag, not 
// right after end flag.
// @dllName: the name of dll.
// @pNewDirectory: a pointer to an import directory to be inserted.
// @pImportLookupTable: a pointer to an import lookup table to be inserted. 
// @pNameTable: a pointer to a name table responding to import lookup table above.
// @pImportAddressTable: IGNORED, since it is same with import lookup table. The function will make a copy of import lookup
// table as IAT.
// The responding import lookup table, hint table, and import address table will be inserted after new import directory.
// Therefore take care of the size of space available. 
STATUS AddNewImportDirectory(IN BYTE* location, IN char* dllName, IN IMAGE_IMPORT_DESCRIPTOR* pNewDirectory, IN IMAGE_THUNK_DATA32* pImportLookupTable, 
							 IN IMAGE_IMPORT_BY_NAME* pNameTable);

// UpdateAddrWithBaseRelocationTable:
//     The function will change ImageBase and update entries of each base relocation block.
// @buffer: the buffer to be operated.
// @newImageBase: new image base.
STATUS UpdateAddrWithBaseRelocationTable(IN PMEMORYBASE buffer, DWORD newImageBase);


//////////////////////////
// Auxiliary Functions:
//////////////////////////

// calculateFileBufferSize:
//     This function will return the size of a file buffer.
// @fileBuffer: base address of file buffer.
// Noting: this function will change PE headers.
DWORD calculateFileBufferSize(IN PMEMORYBASE fileBuffer);

// align:
//     This function will return a size aligned by given align size.
// @size: size of data.
// @alignSize: size of alignment.
DWORD align(DWORD size, DWORD alignSize);

////////////////////////
// Test Functions:
////////////////////////

// TEST_VAToFOA:
//     This function tests validation of the process of translating from virtual address to file offset address, 
// and returns the file offset address in given file buffer.
void TEST_VAToFOA();

// TEST_FileOperation:
//     This function tests following operations:
//     1. read data from file into a memory buffer.
//     2. parse headers.
//     3. transfer from file buffer to image buffer.
//     4. transfer from image buffer to file buffer.
//     5. save file buffer as a file.
void TEST_FileOperation();

// TEST_AddShellCodeToCodeSection:
//     This function will add shell code to code section.
void TEST_AddShellCodeToCodeSection();

// TEST_AddSectionToBuffer:
//     This function will add a new section to a file buffer.
void TEST_AddSectionToBuffer();

// TEST_AddShellCodeToNewSection:
//     This function will add a new shell code to a new section.
void TEST_AddShellCodeToNewSection();

// TEST_ExtensionOfLastSection:
//     This function will extend the size of last section.
void TEST_ExtensionOfLastSection();

// TEST_MergingSections:
//     This function will merge all sections into the first one.
void TEST_MergingSections();

// TEST_SearchFuncAddrByName:
//     This function will test the validation of SearchFuncAddrByName.
void TEST_SearchFuncAddrByName();

// TEST_SearchFuncAddrByOrdinal:
//     This function will test the validation of SearchFuncAddrByOrdinal.
void TEST_SearchFuncAddrByOrdinal();

// TEST_MoveExportDirectoryToNewAddress:
//     This function will test the validation of MoveExportDirectoryToNewAddress.
void TEST_MoveExportDirectoryToNewAddress();

// TEST_MoveBaseRelocationTableToNewAddress:
//     This function will test the validation of MoveBaseRelocationTableToNewAddress.
void TEST_MoveBaseRelocationTableToNewAddress();

// TEST_UpdateAddrWithBaseRelocationTable():
//     This function will test the validation of UpdateAddrWithBaseRelocationTable.
void TEST_UpdateAddrWithBaseRelocationTable();

// TEST_MoveImportDirectoryToNewAddress():
//     This function will test the validation of MoveImportDirectoryToNewAddress.
void TEST_MoveImportDirectoryToNewAddress();

// TEST_AddNewImportDirectory():
//     This function will test the validation of AddNewImportDirectory.
void TEST_AddNewImportDirectory();

#endif // !defined(AFX_TOOLS_H__05760431_89F6_4867_9765_8E2F9A55A832__INCLUDED_)
