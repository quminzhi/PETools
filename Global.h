// Global.h: interface for the Global class.
//     there are only function declaration, type definition, macro definition and extern 
// variable declaration that could be appeared in header file.
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_GLOBAL_H__D35C3410_321B_45F3_ACE9_CB1060F3C7CA__INCLUDED_)
#define AFX_GLOBAL_H__D35C3410_321B_45F3_ACE9_CB1060F3C7CA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <stdio.h>
#include <stdlib.h>

#define FILE_IN "notepad.exe"

// Extension from C++
#define nullptr NULL
#define DEBUG 0
#define TRUE 1
#define FALSE 0

// Descriptor, no practical meaning
#define IN
#define OUT

// Unit
#define BYTE unsigned char
#define WORD unsigned short
#define DWORD unsigned int
#define STATUS unsigned int
#define PFILEBASE unsigned char*
#define PMEMORYBASE unsigned char*

#define SIZEOF_SECTION_NAME 8
#define IMAGE_NT_SIGNATURE 0X00004550
#define IMAGE_SIZEOF_FILE_HEADER 20
#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SIZEOF_EXPORT_DIRECTORY 40
#define IMAGE_SIZEOF_PE_SIGNATURE 4
#define IMAGE_SIZEOF_BASE_RELOCATION 8
#define SIZEOF_DLL_CODE 0x100

// Base Address
extern PMEMORYBASE fileBuffer;
extern PMEMORYBASE imageBuffer;

// Headers
typedef struct dosHeader {
	WORD e_magic;
	BYTE offset[58];  // offset is used to ignore useless members
	DWORD e_lfanew;
} DOSHeader;
extern DOSHeader* pDosHeader;

typedef struct fileHeader {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} FILEHeader;
extern FILEHeader* pFileHeader;

typedef struct optionalHeader {
	WORD Magic;
	DWORD SizeOfCode;
	BYTE offseta[8];
	DWORD AddressOfEntryPoint;
	BYTE offsetb[8];
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	BYTE offsetc[16];
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	BYTE offsetd[4];
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	BYTE offsete[4];
	DWORD NumberOfRvaAndSizes;
	// _IMAGE_DATA_DIRECTORY DataDirectory[16];
} OPTIONALHeader;
extern OPTIONALHeader* pOptionalHeader;

typedef struct image_data_directory {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;
extern IMAGE_DATA_DIRECTORY* pDirectory;

////////////////////////////
// Export Table - Begin

typedef struct image_export_directory {					
    DWORD   Characteristics;	
    DWORD   TimeDateStamp;	
    WORD    MajorVersion;
    WORD    MinorVersion;	
    DWORD   NameRVA;	
    DWORD   OrdinalBase;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;	
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
extern IMAGE_EXPORT_DIRECTORY* pExportDirectory;

typedef struct export_address_table {
	DWORD FuncVirtualAddress;
} EXPORT_ADDRESS_TABLE;
extern EXPORT_ADDRESS_TABLE* pAddressTable;

typedef struct name_pointer_table {
	DWORD NameVirtualAddress;
} NAME_POINTER_TABLE;
extern NAME_POINTER_TABLE* pNamePointerTable;

typedef struct name_ordinal_table {
	WORD Ordinal;
} NAME_ORDINAL_TABLE;
extern NAME_ORDINAL_TABLE* pNameOrdinalTable;

// Export Table - End
/////////////////////////////


///////////////////////////////
// Base Relocation Directory

typedef struct image_base_relocation {				
    DWORD   VirtualAddress;				
    DWORD   SizeOfBlock;				
} IMAGE_BASE_RELOCATION;
extern IMAGE_BASE_RELOCATION* pBaseRelocationBlock;

///////////////////////////////


///////////////////////////////
// Import Table - Begin

typedef struct image_import_descriptor {				
    union {				
        DWORD   Characteristics;           				
        DWORD   OriginalFirstThunk;         				
    };				
    DWORD   TimeDateStamp;               				
    DWORD   ForwarderChain;              				
    DWORD   Name;				
    DWORD   FirstThunk;                 				
} IMAGE_IMPORT_DESCRIPTOR;
extern IMAGE_IMPORT_DESCRIPTOR* pImportDirectory;

typedef struct image_thunk_data32 {				
    union {				
        BYTE*  ForwarderString;				
        DWORD* Function;				
        DWORD Ordinal;				
        struct image_import_by_name*  AddressOfData;				
    } u1;				
} IMAGE_THUNK_DATA32;
extern IMAGE_THUNK_DATA32* pImportLookupTable;
extern IMAGE_THUNK_DATA32* pImportAddressTable;

typedef struct image_import_by_name {			
    WORD    Hint;			
    BYTE    Name[1];			
} IMAGE_IMPORT_BY_NAME;
extern IMAGE_IMPORT_BY_NAME* pNameTable;

// Import Table - End
///////////////////////////////


///////////////////////////////
// Bound Import Table - Begin

typedef struct image_bound_import_descriptor {		
    DWORD   TimeDateStamp;		
    WORD    OffsetModuleName;		
    WORD    NumberOfModuleForwarderRefs;			
} IMAGE_BOUND_IMPORT_DESCRIPTOR;
extern IMAGE_BOUND_IMPORT_DESCRIPTOR* pBoundImportTable;

typedef struct image_bound_forwarder_ref {		
    DWORD   TimeDateStamp;		
    WORD    OffsetModuleName;		
    WORD    Reserved;		
} IMAGE_BOUND_FORWARDER_REF;

// Bound Import Table - End
///////////////////////////////


typedef struct image_section_header {
	char Name[SIZEOF_SECTION_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	BYTE offset[12];
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;
extern IMAGE_SECTION_HEADER* p_section_header;

// Auxiliary tools

// printInMemoryFormat:
//     This function will print memory data in memory format, that is little-endian.
// @addr: address of memory data.
// @size: the size of memory data that will be displayed. 
STATUS printInMemoryFormat(IN BYTE* addr, IN size_t size);

// VAToFOA:
//     The function will translate virtual address to file offset address of a given file buffer.
// @virtualAddress: virtual address of data in image buffer.
// @fileBase: the base address of file buffer.
// VA means absolute virtual address in image buffer
// FOA means absolute file offset address in file buffer
BYTE* VAToFOA(IN BYTE* virtualAddress, IN BYTE* fileBase);

// RVAToFOA:
//     The function will translate relative virtual address to file offset address of a given file buffer.
// @relativeVirtualAddress: relative virtual address of data in image buffer.
// @fileBase: the base address of file buffer.
// RVA means relative virtual address in image buffer
// FOA means absolute file offset address in file buffer
BYTE* RVAToFOA(IN BYTE* relativeVirtualAddress, IN BYTE* fileBase);

// FOAToVA
//     The function will translate file offset address to virtual address of a given image buffer.
// @fileOffsetAddress: file offset address of data in file buffer(+fileBuffer).
// @fileBase: the base address of file buffer.
// VA means absolute virtual address in image buffer
// FOA means absolute file offset address in file buffer
BYTE* FOAToVA(IN BYTE* fileOffsetAddress, IN BYTE* fileBase);

// FOAToRVA
//     The function will translate file offset address to relative virtual address of a given image buffer.
// @fileOffsetAddress: file offset address of data in file buffer(+fileBuffer).
// @fileBase: the base address of file buffer.
// RVA means relative virtual address in image buffer
// FOA means absolute file offset address in file buffer
BYTE* FOAToRVA(IN BYTE* fileOffsetAddress, IN BYTE* fileBase);

#endif // !defined(AFX_GLOBAL_H__D35C3410_321B_45F3_ACE9_CB1060F3C7CA__INCLUDED_)
