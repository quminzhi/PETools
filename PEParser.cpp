// PEParser.cpp: implementation of the PEParser class.
//
//////////////////////////////////////////////////////////////////////

#include "PEParser.h"

void printHeaders() {
	WORD i;
	char name[9];

	printf("======DOS HEADER======\n");
	printf("e_magic: %x\n", pDosHeader->e_magic);
	printf("e_lfanew: %x\n", pDosHeader->e_lfanew);

	if (DEBUG) {
		printf("PEParser.printHeaders:\n");
		printInMemoryFormat((BYTE*)&pDosHeader->e_magic, sizeof(pDosHeader->e_magic));
		printInMemoryFormat((BYTE*)&pDosHeader->e_lfanew, sizeof(pDosHeader->e_lfanew));
		printf("\n");
	}

	printf("\n");

	printf("======File HEADER======\n");
	printf("Machine: %x\n", pFileHeader->Machine);
	printf("NumberOfSections: %x\n", pFileHeader->NumberOfSections);
	printf("TimeDateStamp: %x\n", pFileHeader->TimeDateStamp);
	printf("PointerToSymbolTable: %x\n", pFileHeader->PointerToSymbolTable);
	printf("NumberOfSymbols: %x\n", pFileHeader->NumberOfSymbols);
	printf("SizeOfOptionalHeader: %x\n", pFileHeader->SizeOfOptionalHeader);
	printf("Characteristics: %x\n", pFileHeader->Characteristics);
	printf("\n");

	printf("======Optional HEADER======\n");
	printf("Magic: %x\n", pOptionalHeader->Magic);
	printf("SizeOfCode: %x\n", pOptionalHeader->SizeOfCode);
	printf("AddressOfEntryPoint: %x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("ImageBase: %x\n", pOptionalHeader->ImageBase);
	printf("SectionAlignment: %x\n", pOptionalHeader->SectionAlignment);
	printf("FileAlignment: %x\n", pOptionalHeader->FileAlignment);
	printf("SizeOfImage: %x\n", pOptionalHeader->SizeOfImage);
	printf("SizeOfHeaders: %x\n", pOptionalHeader->SizeOfHeaders);
	printf("CheckSum: %x\n", pOptionalHeader->CheckSum);
	printf("SizeOfStackReserve: %x\n", pOptionalHeader->SizeOfStackReserve);
	printf("SizeOfStackCommit: %x\n", pOptionalHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve: %x\n", pOptionalHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommit: %x\n", pOptionalHeader->SizeOfHeapCommit);
	printf("NumberOfRvaAndSizes: %x\n", pOptionalHeader->NumberOfRvaAndSizes);
	printf("\n");

	printf("======Directory Data======\n");
	printf("Export Table: \n");
	printf("VA: %x,  Size: %x\n", pDirectory[0].VirtualAddress, pDirectory[0].Size);
	printf("Import Table: \n");
	printf("VA: %x,  Size: %x\n", pDirectory[1].VirtualAddress, pDirectory[1].Size);
	printf("Base Relocation Table: \n");
	printf("VA: %x,  Size: %x\n", pDirectory[5].VirtualAddress, pDirectory[5].Size);
	// since 13th table is IAT
	if (pOptionalHeader->NumberOfRvaAndSizes > 0x0C) {
		printf("IAT: \n");
		printf("VA: %x,  Size: %x\n", pDirectory[12].VirtualAddress, pDirectory[12].Size);
	}
	printf("\n");

	printf("======SECTION HEADER======\n");
	for (i = 0; i < pFileHeader->NumberOfSections; i++) {
		printf("Description of SECTION %d:\n", i);
		// a secure way to print name
		memset(name, 0, sizeof(name));
		memcpy(name, p_section_header[i].Name, 8);
		name[8] = '\0';
		printf("Name: %s\n", name);
		printf("Misc: %x\n", p_section_header[i].Misc.VirtualSize);
		printf("VirtualAddress: %x\n", p_section_header[i].VirtualAddress);
		printf("SizeOfRawData: %x\n", p_section_header[i].SizeOfRawData);
		printf("PointerToRawData: %x\n", p_section_header[i].PointerToRawData);
		printf("Characteristics: %x\n", p_section_header[i].Characteristics);
		printf("\n");
	}
}

void printExportDirectory() {
	size_t i;
	printf("======Export Directory======\n");
	printf("Characteristics: %x\n", pExportDirectory->Characteristics);
	printf("TimeDateStamp: %x\n", pExportDirectory->TimeDateStamp);
	printf("MajorVersion: %x\n", pExportDirectory->MajorVersion);
	printf("MinorVersion: %x\n", pExportDirectory->MinorVersion);
	printf("Name RVA: %x\n", pExportDirectory->NameRVA);
	printf("Ordinal Base: %x\n", pExportDirectory->OrdinalBase);
	printf("NumberOfFunctions: %x\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames: %x\n", pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions: %x\n", pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames: %x\n", pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals: %x\n", pExportDirectory->AddressOfNameOrdinals);
	printf("\n");

	printf("======Function Address Table======\n");
	for (i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
		printf("func@%d: %x\n", i, pAddressTable[i].FuncVirtualAddress);
	}
	printf("\n");

	printf("======Name Ordinal Table======\n");
	for (i = 0; i < pExportDirectory->NumberOfNames; i++) {
		printf("%d: %x\n", i, pNameOrdinalTable[i].Ordinal);
	}
	printf("\n");

	printf("======Name Pointer Table======\n");
	for (i = 0; i < pExportDirectory->NumberOfNames; i++) {
		printf("%d: %x --> ", i, pNamePointerTable[i].NameVirtualAddress);
		printf("@%s\n", VAToFOA((BYTE*)(pNamePointerTable[i].NameVirtualAddress + pOptionalHeader->ImageBase), fileBuffer));
	}
	printf("\n");
}

void printBaseRelocationDirectory() {
	size_t numOfBlocks = 0;
	size_t numOfEntry = 0;
	size_t i;
	IMAGE_BASE_RELOCATION* pBlock = pBaseRelocationBlock;
	WORD* pEntry = nullptr;
	WORD entry = 0;
	DWORD rva = 0;

	while (TRUE) {
		// TODO: check End Flag
		if ((pBlock->VirtualAddress == 0) && (pBlock->SizeOfBlock == 0)) {
			break;
		}

		printf("Block %d:\n", numOfBlocks);
		printf("VirtualAddress: %x\n", pBlock->VirtualAddress);
		printf("SizeOfBlock: %x\n", pBlock->SizeOfBlock);

		numOfEntry = (pBlock->SizeOfBlock - 8) / 2;
		// trick here to jump over virtualaddress and size of block
		pEntry = (WORD*)(&pBlock[1].VirtualAddress);
		for (i = 0; i < numOfEntry; i++) {
			entry = pEntry[i];
			// 0000111111111111b = 0x0FFF
			rva = (entry & 0x0FFF) + pBlock->VirtualAddress;
			printf("Entry %d: %x\n", i, rva);
		}
		
		// TODO: update arguments
		numOfBlocks++;
		pBlock = (IMAGE_BASE_RELOCATION*)((DWORD)pBlock + pBlock->SizeOfBlock);
	}

}

void printImportDirectory() {
	size_t i, j;
	WORD* pOrdinal = nullptr;
	DWORD ordinal_mask = 0x80000000;
	IMAGE_IMPORT_BY_NAME* pName = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* pImportDirectoryTable = pImportDirectory;

	printf("======Import Directory======\n");
	printf("Size of Import Directories: %d\n", pDirectory[1].Size);
	for (i = 0; pImportDirectoryTable->OriginalFirstThunk != 0; i++) {
		printf("===========Begin===========\n");
		printf("Import Directory Table [%d]:\n", i);
		printf("Import Lookup Table RVA: %x\n", pImportDirectory[i].OriginalFirstThunk);
		printf("Time/Date Stamp: %x\n", pImportDirectory[i].TimeDateStamp);
		printf("Forwarder Chain: %x\n", pImportDirectory[i].ForwarderChain);
		printf("DLL RVA: %x, Name: %s\n", pImportDirectory[i].Name, RVAToFOA((BYTE*)pImportDirectory[i].Name, fileBuffer));
		printf("Import Address Table RVA: %x\n", pImportDirectory[i].FirstThunk);
		printf("\n");
		
		pImportLookupTable = (IMAGE_THUNK_DATA32*)RVAToFOA((BYTE*)pImportDirectory[i].OriginalFirstThunk, fileBuffer);
		printf("Import Lookup Table [%d]:\n", i);
		for (j = 0; pImportLookupTable[j].u1.Ordinal != 0; j++) {
			if (pImportLookupTable[j].u1.Ordinal & ordinal_mask) {
				// reference by ordinal
				pOrdinal = (WORD*)((DWORD)&pImportLookupTable[j].u1.Ordinal + 2); // get low 2 bytes
				printf("#%d -> ordinal: %d\n", j, *pOrdinal);
			}
			else {
				// reference by name
				pName = (IMAGE_IMPORT_BY_NAME*)RVAToFOA((BYTE*)pImportLookupTable[j].u1.AddressOfData, fileBuffer);
				printf("#%d -> hint: %d, name: %s\n", j, pName->Hint, &pName->Name); // get name address
			}
		}
		printf("\n");
		
		// Import Address Table is same as Import Lookup Table before loading
		pImportAddressTable = (IMAGE_THUNK_DATA32*)RVAToFOA((BYTE*)pImportDirectory[i].FirstThunk, fileBuffer);
		printf("Import Address Table [%d]:\n", i);
		for (j = 0; pImportAddressTable[j].u1.Ordinal != 0; j++) {
			printf("#%d -> addr: %x\n", j, pImportAddressTable[j].u1.Ordinal);
		}
		printf("===========================\n");
		printf("\n");
	
		// do NOT forget to update table pointer
		pImportDirectoryTable++;
	}
}

void printBoundImportDirectory() {
	size_t i;
	WORD j;
	IMAGE_BOUND_FORWARDER_REF* pRef = nullptr;
	IMAGE_BOUND_IMPORT_DESCRIPTOR* pBoundDescriptor = pBoundImportTable;
	for (i = 0; pBoundDescriptor->TimeDateStamp != 0; i++) {
		printf("=============================\n");
		printf("Bound Import Descriptor [%d]\n", i);
		printf("Time/Date Stamp: %x\n", pBoundDescriptor->TimeDateStamp);
		printf("Module Name: %s\n", (char*)((DWORD)pBoundImportTable + pBoundDescriptor->OffsetModuleName));
		printf("NumberOfModuleForwarderRefs: %d\n", pBoundDescriptor->NumberOfModuleForwarderRefs);
		
		pRef = (IMAGE_BOUND_FORWARDER_REF*)((DWORD)pBoundDescriptor + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
		for (j = 0; j < pBoundDescriptor->NumberOfModuleForwarderRefs; j++) {
			printf("\tRef [%d-%d]\n", i, j);
			printf("\tTime/Date Stamp: %x\n", pRef[i].TimeDateStamp);
			printf("\tModule Name: %s\n", (char*)((DWORD)pBoundImportTable + pRef[j].OffsetModuleName));
		}
		printf("============================\n");
		
		// update pointer: the length of a descriptor and n reference structure
		pBoundDescriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(&pRef[j]);
	}
}


STATUS PEParser(IN PMEMORYBASE filebase) {
	DWORD* pNTHeader = nullptr;
	pDosHeader = (DOSHeader*)filebase;
	
	// Check PE Signature: 
	// Noting that it is a good behavior to add type conversion for pointer arithmetic operation
	pNTHeader = (DWORD*)((DWORD)filebase + pDosHeader->e_lfanew);

	if (*pNTHeader != IMAGE_NT_SIGNATURE) {
		printf("Check PE Signature failure: PE Signature is not found.\n");
		return 254;
	}
    
	// Update pointers to headers
	pFileHeader = (FILEHeader*)((DWORD)pNTHeader + 4);
	pOptionalHeader = (OPTIONALHeader*)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	p_section_header = (IMAGE_SECTION_HEADER*)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	// Update directory pointer
	pDirectory = (IMAGE_DATA_DIRECTORY*)((DWORD)pOptionalHeader + DIRECTORY_OFFSET);

	// Update export directory
	if (pDirectory[0].VirtualAddress != 0) {
		// since virtual address here is rva, we have to add image base to transfer it to va.
		pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)VAToFOA((BYTE*)(pDirectory[0].VirtualAddress + pOptionalHeader->ImageBase), fileBuffer);
		pAddressTable = (EXPORT_ADDRESS_TABLE*)VAToFOA((BYTE*)(pExportDirectory->AddressOfFunctions + pOptionalHeader->ImageBase), fileBuffer);
		pNamePointerTable = (NAME_POINTER_TABLE*)VAToFOA((BYTE*)(pExportDirectory->AddressOfNames + pOptionalHeader->ImageBase), fileBuffer);
		pNameOrdinalTable = (NAME_ORDINAL_TABLE*)VAToFOA((BYTE*)(pExportDirectory->AddressOfNameOrdinals + pOptionalHeader->ImageBase), fileBuffer);
	}

	// Update base relocation directory, the sixth table in data directory.
	if (pDirectory[5].VirtualAddress != 0) {
		pBaseRelocationBlock = (IMAGE_BASE_RELOCATION*)VAToFOA((BYTE*)(pDirectory[5].VirtualAddress + pOptionalHeader->ImageBase), fileBuffer);
	}
	
	// Update import directory
	if (pDirectory[1].VirtualAddress != 0) {
		pImportDirectory = (IMAGE_IMPORT_DESCRIPTOR*)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer);
	}

	// Update bound import table, the 12th table in data directory.
	if (pDirectory[11].VirtualAddress != 0) {
		pBoundImportTable = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)RVAToFOA((BYTE*)pDirectory[11].VirtualAddress, fileBuffer);
	}

	if (DEBUG) {
		printf("PEParser.PEParser:\n");
		printf("pDosHeader->e_lfanew: %x\n", pDosHeader->e_lfanew);
		printf("filebas: %x\n", (DWORD)filebase);
		printf("(DWORD)filebase + pDosHeader->e_lfanew = %x\n", (DWORD)filebase + pDosHeader->e_lfanew);
		printf("\n");
	}

	return 0;
}

void TEST_PrintImportDirectoryTable() {
	STATUS ret;
	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	printImportDirectory();

	free(fileBuffer);
}

void TEST_PrintBoundImportDirectory() {
	STATUS ret;
	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printBoundImportDirectory();

	free(fileBuffer);
}
