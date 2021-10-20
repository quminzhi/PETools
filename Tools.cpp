// Tools.cpp: implementation of the Tools class.
//
//////////////////////////////////////////////////////////////////////

#include "Tools.h"

int isMatched(char* foaAddr, char* name);

STATUS FileBufferToImageBuffer(IN PMEMORYBASE fileBuffer, OUT PMEMORYBASE* imageBuffer) {
	DWORD i;
	// memory allocation for image buffer
	PMEMORYBASE imgBuffer = (PMEMORYBASE)malloc(sizeof(BYTE) * pOptionalHeader->SizeOfImage);
	if (imgBuffer == nullptr) {
		printf("Memory allocation failed.\n");
		return 255;
	}
	memset(imgBuffer, 0, pOptionalHeader->SizeOfImage);

	// copy headers
	memcpy(imgBuffer, fileBuffer, pOptionalHeader->SizeOfHeaders);

	// copy sections
	for (i = 0; i < pFileHeader->NumberOfSections; i++) {
		memcpy(&imgBuffer[p_section_header[i].VirtualAddress], &fileBuffer[p_section_header[i].PointerToRawData], sizeof(BYTE) * p_section_header[i].SizeOfRawData);
	}
	
	if (DEBUG) {
		printf("Tools.FileBufferToImageBuffer:\n");
		printf("file buffer: %x\n", fileBuffer);
		printf("image buffer: %x\n", imgBuffer);
		printf("\n");
	}

	*imageBuffer = imgBuffer;
	imgBuffer = nullptr;

	return 0;
}



STATUS ImageBufferToFileBuffer(IN PMEMORYBASE imageBuffer, OUT PMEMORYBASE* rt_fileBuffer) {
	DWORD i;
	DWORD sizeOfFileBuffer = 0;

	
	// memory allocation for file buffer
	sizeOfFileBuffer = calculateFileBufferSize(imageBuffer);
	PMEMORYBASE	newFileBuffer = (PMEMORYBASE)malloc(sizeof(BYTE) * sizeOfFileBuffer);
	if (newFileBuffer == nullptr) {
		printf("Memory allocation failed.\n");
		return 255;
	}
	memset(newFileBuffer, 0, sizeOfFileBuffer);

	// copy headers
	memcpy(newFileBuffer, imageBuffer, pOptionalHeader->SizeOfHeaders);

	// copy sections
	for (i = 0; i < pFileHeader->NumberOfSections; i++) {
		memcpy(&fileBuffer[p_section_header[i].PointerToRawData], &imageBuffer[p_section_header[i].VirtualAddress], sizeof(BYTE) * p_section_header[i].SizeOfRawData);
	}

	*rt_fileBuffer = fileBuffer;
	fileBuffer = nullptr;

	if (DEBUG) {
		printf("Tools.ImageBufferToFileBuffer:\n");
		printf("image buffer: %x\n", imageBuffer);
		printf("file buffer: %x\n", *rt_fileBuffer);
		printf("\n");
	}

	return 0;
}

STATUS AddSectionToBuffer(IN PMEMORYBASE fileBuffer, IN IMAGE_SECTION_HEADER* newSection, OUT PMEMORYBASE* newFileBuffer) {
	DWORD new_e_lfanew = 0x40;
	PMEMORYBASE newBuffer = nullptr;
	DWORD filesize = calculateFileBufferSize(fileBuffer);
	DWORD newFilesize = 0;
	BYTE* startPoint = nullptr;
	DWORD numOfLastSection = pFileHeader->NumberOfSections - 1;
	DWORD sizeOfHeadersFromPESignature = 0;

	// check if there is enough space for new section
	DWORD remain = 0;
	remain = pOptionalHeader->SizeOfHeaders - pDosHeader->e_lfanew - IMAGE_SIZEOF_PE_SIGNATURE - IMAGE_SIZEOF_FILE_HEADER - pFileHeader->SizeOfOptionalHeader - pFileHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
	if (remain < 2 * IMAGE_SIZEOF_SECTION_HEADER) {
		printf("No memory available for a new section header.\n");
		return 255;
	}
	
	// update value of new section
	newSection->Characteristics = newSection->Characteristics | 0x60000020;
	// file alignment
	newSection->SizeOfRawData = align(newSection->Misc.PhysicalAddress, pOptionalHeader->FileAlignment);
	// newSection->SizeOfRawData = ((newSection->Misc.PhysicalAddress - 1) / pOptionalHeader->FileAlignment + 1) * pOptionalHeader->FileAlignment;
	// section alignment
	newSection->PointerToRawData = p_section_header[numOfLastSection].PointerToRawData + p_section_header[numOfLastSection].SizeOfRawData;
	// here assuming that SizeOfRawData > VirtualSize
	newSection->VirtualAddress = p_section_header[numOfLastSection].VirtualAddress + align(p_section_header[numOfLastSection].SizeOfRawData, pOptionalHeader->SectionAlignment);
	// newSection->VirtualAddress = p_section_header[numOfLastSection].VirtualAddress + ((p_section_header[numOfLastSection].SizeOfRawData - 1) / pOptionalHeader->SectionAlignment + 1) * pOptionalHeader->SectionAlignment;

	// modify the SizeOfImage, section alignment IMPORTANT
	pOptionalHeader->SizeOfImage = newSection->VirtualAddress + align(newSection->SizeOfRawData, pOptionalHeader->SectionAlignment);
	
	// elevate headers
	if (pDosHeader->e_lfanew > new_e_lfanew) {
		sizeOfHeadersFromPESignature = IMAGE_SIZEOF_PE_SIGNATURE + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + pFileHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
		memcpy((PMEMORYBASE)((DWORD)fileBuffer + new_e_lfanew), (PMEMORYBASE)((DWORD)fileBuffer + pDosHeader->e_lfanew), sizeOfHeadersFromPESignature);
		pDosHeader->e_lfanew = new_e_lfanew;
		// update pointers to headers
		PEParser(fileBuffer);
	}

	// copy new section to section table
	startPoint = (BYTE*)((DWORD)&p_section_header[numOfLastSection+1]);
	memcpy(startPoint, newSection, IMAGE_SIZEOF_SECTION_HEADER);
	startPoint = (BYTE*)((DWORD)&p_section_header[numOfLastSection+2]);
	memset(startPoint, 0, IMAGE_SIZEOF_SECTION_HEADER);

	// modify the value of NumberOfSections in FileHeader.
	pFileHeader->NumberOfSections += 1;

	// add a new section at the end of the last section
	newFilesize = filesize + newSection->SizeOfRawData;
	newBuffer = (PMEMORYBASE)malloc(sizeof(BYTE) * newFilesize);
	memset(newBuffer, 0, sizeof(BYTE) * newFilesize);
	memcpy(newBuffer, fileBuffer, filesize);

	*newFileBuffer = newBuffer;
	newBuffer = nullptr;
	
	return 0;
}

STATUS ExtensionOfLastSection(IN PMEMORYBASE fileBuffer, IN DWORD addition, OUT PMEMORYBASE* newFileBuffer) {
	STATUS ret;
	PMEMORYBASE imgBuffer = nullptr;
	PMEMORYBASE imgBuffer_ext = nullptr;
	DWORD last = pFileHeader->NumberOfSections - 1;
	DWORD newSize = 0;

	ret = FileBufferToImageBuffer(fileBuffer, &imgBuffer);

	// TODO: allocate new img buffer and modify SizeOfImage
	imgBuffer_ext = (PMEMORYBASE)malloc(sizeof(BYTE) * pOptionalHeader->SizeOfImage + addition);
	memset(imgBuffer_ext, 0, sizeof(BYTE) * pOptionalHeader->SizeOfImage + addition);
	memcpy(imgBuffer_ext, imgBuffer, pOptionalHeader->SizeOfImage);

	// parse members of new buffer
	ret = PEParser(imgBuffer_ext);

	pOptionalHeader->SizeOfImage += addition;

	// TODO: modify section header of the last one
	newSize = p_section_header[last].Misc.VirtualSize > p_section_header[last].SizeOfRawData ? p_section_header[last].Misc.VirtualSize : p_section_header[last].SizeOfRawData;
	p_section_header[last].Misc.VirtualSize = align(align(newSize, pOptionalHeader->SectionAlignment) + addition, pOptionalHeader->SectionAlignment);
	p_section_header[last].SizeOfRawData = align(align(newSize, pOptionalHeader->SectionAlignment) + addition, pOptionalHeader->FileAlignment);

	// TODO: save as file buffer
	ret = ImageBufferToFileBuffer(imgBuffer_ext, newFileBuffer);

	free(imgBuffer);
	free(imgBuffer_ext);

	return 0;
}

STATUS MergingSections(IN PMEMORYBASE fileBuffer, OUT PMEMORYBASE* newFileBuffer) {
	STATUS ret;
	PMEMORYBASE imgBuffer = nullptr;
	DWORD newCharacteristics = 0;
	DWORD i;

	ret = FileBufferToImageBuffer(fileBuffer, &imgBuffer);
	
	// parse new buffer
	ret = PEParser(imgBuffer);
	
	// TODO: update members of new buffer
	// record characteristics of each section and update characteristics
	for (i = 0; i < pFileHeader->NumberOfSections; i++) {
		newCharacteristics = newCharacteristics | p_section_header[i].Characteristics;
	}
	p_section_header[0].Characteristics = newCharacteristics;
	// update virtual size
	p_section_header[0].Misc.VirtualSize = pOptionalHeader->SizeOfImage - p_section_header[0].VirtualAddress;
	// update size of raw data
	p_section_header[0].SizeOfRawData = align(p_section_header[0].Misc.VirtualSize, pOptionalHeader->FileAlignment);

	// update number of sections
	pFileHeader->NumberOfSections = 1;

	ret = ImageBufferToFileBuffer(imgBuffer, newFileBuffer);

	free(imgBuffer);

	return 0;
}

size_t searchExportNamePointerTable(char* name) {
	size_t index = -1;
	size_t i = 0;
	BYTE* nameFOAAddr = nullptr;
	
	for (i = 0; i < pExportDirectory->NumberOfNames; i++) {
		nameFOAAddr = VAToFOA((BYTE*)(pNamePointerTable[i].NameVirtualAddress + pOptionalHeader->ImageBase), fileBuffer);
		if (isMatched((char*)nameFOAAddr, (char*)name)) {
			index = i;
			break;
		}
	}

	return index;
}

DWORD SearchFuncAddrByName(IN PMEMORYBASE buffer, char* name) {
	WORD ordinal;
	DWORD rva;
	size_t i = searchExportNamePointerTable(name);
	
	if (i == -1) {
		printf("No matching function name founded.\n");
		exit(-1);
	}

	ordinal = pNameOrdinalTable[i].Ordinal;
	
	rva = pAddressTable[ordinal].FuncVirtualAddress;
	
	return rva;
}


size_t searchNameOrdinalTable(WORD ordinal) {
	size_t index = -1;
	size_t i;

	for (i = 0; i < pExportDirectory->NumberOfNames; i++) {
		if (ordinal == pNameOrdinalTable[i].Ordinal) {
			index = i;
			break;
		}
	}

	return index;
}

DWORD SearchFuncAddrByOrdinal(IN PMEMORYBASE buffer, WORD biasedOrdinal) {
	DWORD rva;
	BYTE* name;
	WORD ordinal = biasedOrdinal - pExportDirectory->OrdinalBase;
	size_t index = searchNameOrdinalTable(ordinal);

	rva = pAddressTable[ordinal].FuncVirtualAddress;
	name = (BYTE*)(VAToFOA((BYTE*)(pNamePointerTable[index].NameVirtualAddress + pOptionalHeader->ImageBase), fileBuffer));

	printf("Name of function: %s\n", name);

	return rva;
}


STATUS MoveExportDirectoryToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer) {
	size_t i;
	BYTE* ptrName; // file offset address of original public name 
	BYTE* newNameAddr; // pointer to new public name in new section
	NAME_POINTER_TABLE* newNamePointerTable = nullptr;
	size_t length = 0;
	BYTE* begin = location; // track the address where to copy table
	STATUS totalSize = 0;

	// TODO: copy address table
	length = pExportDirectory->NumberOfFunctions * sizeof(DWORD);
	memcpy(begin, pAddressTable, length);
	pAddressTable = (EXPORT_ADDRESS_TABLE*)begin;
	
	// TODO: copy name ordinal table
	begin = (BYTE*)((DWORD)begin + length);
	length = pExportDirectory->NumberOfNames * sizeof(WORD);
	memcpy(begin, pNameOrdinalTable, length);
	pNameOrdinalTable = (NAME_ORDINAL_TABLE*)begin;
	
	// TODO: copy name pointer table
	length = pExportDirectory->NumberOfNames * sizeof(DWORD);
	begin = (BYTE*)((DWORD)begin + length);
	memcpy(begin, pNamePointerTable, length);
	newNamePointerTable = (NAME_POINTER_TABLE*)begin;
	
	// TODO: copy all public name and update pointers in new memory
	newNameAddr = (BYTE*)((DWORD)begin + length); 
	for (i = 0; i < pExportDirectory->NumberOfNames; i++) {
		ptrName = (BYTE*)RVAToFOA((BYTE*)pNamePointerTable[i].NameVirtualAddress, buffer);
		length = strlen((char*)ptrName);
		// +1 for '\0'
		memcpy(newNameAddr, ptrName, length + 1);
		// update address
		newNamePointerTable[i].NameVirtualAddress = (DWORD)FOAToRVA(newNameAddr, buffer);

		// update newNameAddr
		newNameAddr = (BYTE*)((DWORD)newNameAddr + length + 1);
	}
	pNamePointerTable = newNamePointerTable;

	// TODO: copy image export directory
	// TIP: after looping above, newNameAddr will point to the end of address of the last public name
	begin = newNameAddr;
	memcpy(begin, pExportDirectory, IMAGE_SIZEOF_EXPORT_DIRECTORY);
	pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)begin;
	// update table address
	pExportDirectory->AddressOfFunctions = (DWORD)FOAToRVA((BYTE*)pAddressTable, buffer);
	pExportDirectory->AddressOfNameOrdinals = (DWORD)FOAToRVA((BYTE*)pNameOrdinalTable, buffer);
	pExportDirectory->AddressOfNames = (DWORD)FOAToRVA((BYTE*)pNamePointerTable, buffer);

	// TODO: update address of export directory in image data directory
	pDirectory[0].VirtualAddress = (DWORD)FOAToRVA((BYTE*)pExportDirectory, buffer);
	
	totalSize = (DWORD)begin - (DWORD)location +  IMAGE_SIZEOF_EXPORT_DIRECTORY;

	return totalSize;
}

STATUS MoveBaseRelocationTableToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer) {
	BYTE* begin = location;
	IMAGE_BASE_RELOCATION* pBlock = pBaseRelocationBlock;
	DWORD totalSize = 0;

	while (TRUE) {
		// TODO: check End Flag
		if ((pBlock->VirtualAddress == 0) && (pBlock->SizeOfBlock == 0)) {
			// do NOT forget copy End Flag when jump out
			memcpy(begin, pBlock, IMAGE_SIZEOF_BASE_RELOCATION);
			break;
		}
		
		// TODO: copy block
		memcpy(begin, pBlock, pBlock->SizeOfBlock);

		begin = (BYTE*)((DWORD)begin + pBlock->SizeOfBlock);
		pBlock = (IMAGE_BASE_RELOCATION*)((DWORD)pBlock + pBlock->SizeOfBlock);
	}

	// TODO: update address of base relocation table in image data directory
	pDirectory[5].VirtualAddress = (DWORD)FOAToRVA((BYTE*)location, buffer);
	
	totalSize = (DWORD)begin - (DWORD)location + IMAGE_SIZEOF_BASE_RELOCATION;

	return totalSize;
}

STATUS MoveImportDirectoryToNewAddress(IN BYTE* location, IN PMEMORYBASE buffer) {
	// Assume that size of raw data is 0x3000
	// TODO: move all image import descriptors to location
	IMAGE_IMPORT_DESCRIPTOR* pDescriptor = pImportDirectory;
	IMAGE_IMPORT_DESCRIPTOR* newDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)location;
	IMAGE_THUNK_DATA32* newLookupTable = nullptr;
	IMAGE_THUNK_DATA32* pLookupTable = nullptr;
	IMAGE_IMPORT_BY_NAME* newName = nullptr;
	IMAGE_IMPORT_BY_NAME* pName = nullptr;
	size_t i;
	DWORD ordinal_mask = 0x80000000;
	size_t END_FLAG = 0;
	DWORD newNameAddr = 0;
	DWORD newOriginalThunkAddr = 0;
	DWORD OFFSET = 0x1000;

	while (pDescriptor->OriginalFirstThunk != 0) {
		memcpy(newDescriptor, pDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		
		// update pointer
		newDescriptor++;
		pDescriptor++;
	}

	// add zero-padding end flag
	memset(newDescriptor, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	newDescriptor++;

	// relay end address to lookup table, and reset to start of descriptor
	newDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)location;

	// TODO: 
	// 1. move lookup table at 0x1000 offset to the begin of the section.
	// 2. move name table at 0x2000 offset to the begin of the section.
	newLookupTable = (IMAGE_THUNK_DATA32*)((DWORD)location + OFFSET);
	newName = (IMAGE_IMPORT_BY_NAME*)((DWORD)location + OFFSET * 2);	
	
	while (newDescriptor->OriginalFirstThunk != 0) {
		pLookupTable = (IMAGE_THUNK_DATA32*)RVAToFOA((BYTE*)newDescriptor->OriginalFirstThunk, fileBuffer);
		for (i = 0; pLookupTable[i].u1.Ordinal != 0; i++) {
			if (pLookupTable[i].u1.Ordinal & ordinal_mask) {
				// reference by ordinal
				// TODO: 
				// 1. copy name to new name (ordinal with size of DWORD)
				pName = (IMAGE_IMPORT_BY_NAME*)RVAToFOA((BYTE*)pLookupTable[i].u1.Ordinal, fileBuffer);
				memcpy(newName, pName, sizeof(DWORD));
				// 2. update new lookup table
				newNameAddr = (DWORD)FOAToRVA((BYTE*)&newName->Hint, fileBuffer);
				memcpy(&newLookupTable[i].u1.Ordinal, &newNameAddr, sizeof(DWORD));
				// 3. update pointer: consider that each entry of name table has various length
				newName = (IMAGE_IMPORT_BY_NAME*)((DWORD)newName + sizeof(WORD));
			}
			else {
				// reference by name
				// TODO: 
				// 1. copy name to new name
				pName = (IMAGE_IMPORT_BY_NAME*)RVAToFOA((BYTE*)pLookupTable[i].u1.Ordinal, fileBuffer);
				// notice that: hint(WORD) + name(String) + 1('\0')
				memcpy(newName, &pName->Hint, sizeof(WORD) + strlen((char*)&pName->Name) + 1);
				// 2. update new lookup table
				newNameAddr = (DWORD)FOAToRVA((BYTE*)&newName->Hint, fileBuffer);
				memcpy(&newLookupTable[i].u1.Ordinal, &newNameAddr, sizeof(DWORD));
				// 3. update pointer:
				newName = (IMAGE_IMPORT_BY_NAME*)((DWORD)newName + sizeof(WORD) + strlen((char*)&pName->Name) + 1);
			}
		}

		// add end flag to lookup table and name table
		memcpy(newName, &END_FLAG, sizeof(DWORD));
		memcpy(&newLookupTable[i], &END_FLAG, sizeof(DWORD));
		
		// update rva in import descriptor
		newOriginalThunkAddr = (DWORD)FOAToRVA((BYTE*)newLookupTable, fileBuffer);
		newDescriptor->OriginalFirstThunk = newOriginalThunkAddr;
		
		// update newLookupTable and newName for next descriptor
		newLookupTable = (IMAGE_THUNK_DATA32*)((DWORD)&newLookupTable[i] + sizeof(DWORD));
		newName = (IMAGE_IMPORT_BY_NAME*)((DWORD)newName + sizeof(DWORD));
		newDescriptor++;
	}

	// modify relative virtual address in data directory
	pDirectory[1].VirtualAddress = (DWORD)FOAToRVA(location, fileBuffer);
	// update global variable
	pImportDirectory = (IMAGE_IMPORT_DESCRIPTOR*)location;

	return 0;
}

////////////////////////////////////////////
// Helper Functions for AddNewImportDirectory
////////////////////////////////////////////

// return end address
BYTE* AddLookupTable(IN BYTE* location, IN IMAGE_THUNK_DATA32* pImportLookupTable) {
	// copy data
	while (pImportLookupTable->u1.Ordinal != 0) {
		memcpy(location, pImportLookupTable, sizeof(IMAGE_THUNK_DATA32));
		pImportLookupTable++;
		location += sizeof(IMAGE_THUNK_DATA32);
	}
	
	// copy end flag
	memset(location, 0, sizeof(IMAGE_THUNK_DATA32));
	location += sizeof(IMAGE_THUNK_DATA32);

	return location;
}

BYTE* AddNameTable(IN BYTE* location, IN IMAGE_IMPORT_BY_NAME* pNameTable) {
	// copy data
	// while (pNameTable->Name != 0): this is false since Name is the size of byte,
	// which only saves the first character of a name string.
	while (strlen((char*)&pNameTable->Name) != 0) {
		memcpy(location, pNameTable, sizeof(IMAGE_IMPORT_BY_NAME));
		pNameTable++;
		location += sizeof(IMAGE_IMPORT_BY_NAME);
	}

	// copy end flag
	memset(location, 0, sizeof(IMAGE_IMPORT_BY_NAME));
	location += sizeof(IMAGE_IMPORT_BY_NAME);

	return location;
}

BYTE* AddImportAddressTable(IN BYTE* location, IN IMAGE_THUNK_DATA32* pImportAddressTable) {
	// copy data
	while (pImportAddressTable->u1.Ordinal != 0) {
		memcpy(location, pImportAddressTable, sizeof(IMAGE_THUNK_DATA32));
		pImportAddressTable++;
		location += sizeof(IMAGE_THUNK_DATA32);
	}
	
	// copy end flag
	memset(location, 0, sizeof(IMAGE_THUNK_DATA32));
	location += sizeof(IMAGE_THUNK_DATA32);

	return location;
}

STATUS AddNewImportDirectory(IN BYTE* location, IN char* dllName, IN IMAGE_IMPORT_DESCRIPTOR* pNewDirectory, IN IMAGE_THUNK_DATA32* pImportLookupTable, 
							 IN IMAGE_IMPORT_BY_NAME* pNameTable) {
	IMAGE_IMPORT_DESCRIPTOR* pDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)location;
	IMAGE_THUNK_DATA32* pNewLookupTable = nullptr;
	IMAGE_IMPORT_BY_NAME* pNewNameTable = nullptr;
	IMAGE_THUNK_DATA32* pNewAddressTable = nullptr;
	BYTE* endAddr = nullptr;
	BYTE* nameAddr = nullptr;
	size_t offset = 0x10;

	// TODO: copy new directory to location
	// hint: *2 since the last is used as zero-padding end flag
	memset(location, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
	memcpy(pDescriptor, pNewDirectory, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	endAddr = location + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

	// TODO: copy related tables and update addresses in descriptor
	// copy import lookup table
	pNewLookupTable = (IMAGE_THUNK_DATA32*)(endAddr + offset);
	IMAGE_THUNK_DATA32* pNewLookupTable_bk = pNewLookupTable;
	pDescriptor->OriginalFirstThunk = (DWORD)FOAToRVA(endAddr + offset, fileBuffer);
	endAddr = AddLookupTable(endAddr + offset, pImportLookupTable);
	
	// copy and update dll name
	nameAddr = endAddr + offset;
	strcpy((char*)nameAddr, dllName);
	pDescriptor->Name = (DWORD)FOAToRVA(nameAddr, fileBuffer);
	endAddr += offset + strlen(dllName);

	// copy name table
	pNewNameTable = (IMAGE_IMPORT_BY_NAME*)(endAddr + offset);
	endAddr = AddNameTable(endAddr + offset, pNameTable);

	// update lookup table: assume that the size of lookup table equals that of name table
	// do NOT forget to set highest significant bit as 0 to declare that it is referred by name
	while (pNewLookupTable->u1.Ordinal != 0) {
		pNewLookupTable->u1.Ordinal = (DWORD)FOAToRVA((BYTE*)pNewNameTable, fileBuffer) & 0x7fffffff;
		pNewLookupTable++;
		pNewNameTable++;
	}
	
	// copy import address table
	pDescriptor->FirstThunk = (DWORD)FOAToRVA(endAddr + offset, fileBuffer);
	endAddr = AddImportAddressTable(endAddr + offset, pNewLookupTable_bk);

	// TODO: change size of directory
	pDirectory[1].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	return 0;
}


STATUS UpdateAddrWithBaseRelocationTable(IN PMEMORYBASE buffer, DWORD newImageBase) {
	size_t i;
	IMAGE_BASE_RELOCATION* pBlock = pBaseRelocationBlock;
	DWORD numOfEntries = 0;
	WORD* pEntry = nullptr;
	WORD entry = 0;
	WORD flag = 0;
	DWORD rva = 0;
	BYTE* foa = nullptr;
	DWORD* addr = nullptr;
	DWORD new_addr = 0;

	while (TRUE) {
		if ((pBlock->VirtualAddress == 0) && (pBlock->SizeOfBlock == 0)) {
			break;
		}
		
		// TODO: update entry of each block
		numOfEntries = (pBlock->SizeOfBlock - 8) / 2;
		pEntry = (WORD*)((DWORD)pBlock + IMAGE_SIZEOF_BASE_RELOCATION);
		for (i = 0; i < numOfEntries; i++) {
			entry = pEntry[i];
			flag = entry & 0xF000;
			rva = (entry & 0x0FFF) + pBlock->VirtualAddress;
			if (flag == 0x3000) {
				// update address the entry points to 
				foa = RVAToFOA((BYTE*)rva, buffer);
				addr = (DWORD*)foa;
				new_addr = *addr + (newImageBase - pOptionalHeader->ImageBase);
				memcpy(foa, &new_addr, sizeof(DWORD));
			}
		}

		// go to next block
		pBlock = (IMAGE_BASE_RELOCATION*)((DWORD)pBlock + pBlock->SizeOfBlock);
	}

	pOptionalHeader->ImageBase = newImageBase;

	return 0;
}




/////////////////////////////
// Auxiliary Functions:
STATUS SaveBufferAsFile(IN char* filename, IN PMEMORYBASE buffer) {
	FILE *stream;
	int flag = 0;
	DWORD filesize = calculateFileBufferSize(buffer);
	
	if ((stream = fopen(filename, "wb")) != nullptr) {
		flag = fwrite(buffer, sizeof(BYTE), filesize, stream);

		if (!flag) {
			printf("Failed to write file.\n");
			fclose(stream);
			return 255;
		}

		fclose(stream);
		printf("Completed to save to a file.\n");

		return 0;
	}
	else {
		printf("Failed to open a new file.\n");
		return 254;
	}
}

int isMatched(char* foaAddr, char* name) {
	if (strcmp(foaAddr, name)) {
		return 1;
	}
	else {
		return 0;
	}
}

DWORD calculateFileBufferSize(IN PMEMORYBASE fileBuffer) {
	DWORD i;
	DWORD sizeOfFileBuffer = 0;
	STATUS ret;
	
	// update headers
	ret = PEParser(fileBuffer);

	if (DEBUG) {
		printf("Tools.calculateFileBufferSize:\n");
		printf("DOSHeader: %x\n", pDosHeader);
		printf("FileHeader: %x\n", pFileHeader);
		printf("OptionalHeader: %x\n", pOptionalHeader);
		printf("\n");
	}

	sizeOfFileBuffer = pOptionalHeader->SizeOfHeaders;
	for (i = 0; i < pFileHeader->NumberOfSections; i++) {
		sizeOfFileBuffer += p_section_header[i].SizeOfRawData;
	}

	return sizeOfFileBuffer;
}


DWORD align(DWORD size, DWORD alignSize) {
	DWORD ret = ((size - 1) / alignSize + 1) * alignSize;
	return ret;
}


///////////////////////////////
// Test Functions:

void TEST_VAToFOA() {
	STATUS ret;
	PMEMORYBASE fileBuffer = nullptr;
	PMEMORYBASE imgBuffer = nullptr;
	BYTE* fileAddr = nullptr;
	BYTE* virtualAddr = nullptr;

	// Initialize pointers
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
	
	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);

	// memory allocation for a image buffer
	imgBuffer = (PMEMORYBASE)malloc(sizeof(BYTE) * pOptionalHeader->SizeOfImage);
	if (imgBuffer == nullptr) {
		printf("Failed to allocate memory.\n");
		exit(-1);
	}
	memset(imgBuffer, 0, sizeof(BYTE) * pOptionalHeader->SizeOfImage);
	
	// simulate memory allocation for image base
	pOptionalHeader->ImageBase = (DWORD)imgBuffer;

	// test for legal address of a section
	virtualAddr = (BYTE*)((DWORD)pOptionalHeader->ImageBase + p_section_header[0].VirtualAddress + 10);
	// test for illegal address of a section
	// virtualAddr = (BYTE*)((DWORD)pOptionalHeader->ImageBase + p_section_header[0].VirtualAddress - 10);
	fileAddr = VAToFOA(virtualAddr, fileBuffer);
	
	printf("Tools.TEST_VAToFOA:\n");
	printf("virtual address: %x\n", virtualAddr);
	printf("file address: %x\n", fileAddr);
	printf("\n");

	free(fileBuffer);
	free(imageBuffer);
}

void TEST_FileOperation() {
	STATUS ret;
	PMEMORYBASE newFileBuffer = nullptr;

	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
	
	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
//	printExportDirectory();
//	printBaseRelocationDirectory();

	ret = FileBufferToImageBuffer(fileBuffer, &imageBuffer);
	ret = ImageBufferToFileBuffer(imageBuffer, &newFileBuffer);
	ret = SaveBufferAsFile("new_notepad.exe", fileBuffer);

	free(newFileBuffer);
	free(fileBuffer);
	free(imageBuffer);
}

void TEST_AddShellCodeToCodeSection() {
	STATUS ret;
	DWORD offset_to_end_of_code = 10;
	BYTE SHELL_CODE[] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
						  0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00,
						  0x00, 0x00 };
	// this value is different from machine to machine
	BYTE* AddrOfMessageBox = (BYTE*)0x77D5050B;
	DWORD size_of_available_space = 0;
	// code section number
	DWORD section_num = 0;
	// where to insert
	BYTE* startPoint = nullptr;
	BYTE* virtualAddress = nullptr;
	BYTE* addr_in_hardcode = nullptr;
	BYTE* EntryPoint;
	
	// initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();

	// check if space is available and enough to write shell code
	size_of_available_space = p_section_header[section_num].SizeOfRawData - p_section_header[section_num].Misc.VirtualSize;
	if (size_of_available_space <= sizeof(SHELL_CODE)) {
		printf("ERROR: memory space is not enough.\n");
		exit(-1);
	}
	
	// copy shell code to code section
	// 6A 00 6A 00 6A 00 6A 00 E8 00 00 00 00 E9 00 00 00 00 
	startPoint = (BYTE*)((DWORD)fileBuffer + p_section_header[section_num].PointerToRawData + p_section_header[section_num].Misc.VirtualSize + offset_to_end_of_code);
	memcpy(startPoint, SHELL_CODE, sizeof(SHELL_CODE));

	
	// copy hard code of call address to memory space next to E8
	// 6A 00 6A 00 6A 00 6A 00 E8 AC 7D D4 76 E9 00 00 00 00 
	virtualAddress = FOAToVA(startPoint + 8, fileBuffer);
	// transform with hard code equation
	addr_in_hardcode = (BYTE*)((DWORD)AddrOfMessageBox - (DWORD)virtualAddress - 5);
	memcpy(startPoint + 9, &addr_in_hardcode, sizeof(DWORD));

	if (DEBUG) {
		printf("Tools.TEST_AddShellCodeToCodeSection:\n");
		printf("start point: %x\n", startPoint);
		printf("virtual address of call: %x, hard code: %x\n", virtualAddress, addr_in_hardcode);
	}

	// copy hard code of jmp address to memory space next to E9
	// 6A 00 6A 00 6A 00 6A 00 E8 AC 7D D4 76 E9 39 EC FF FF 
	EntryPoint = (BYTE*)((DWORD)pOptionalHeader->ImageBase + (DWORD)pOptionalHeader->AddressOfEntryPoint);
	virtualAddress = FOAToVA(startPoint + 13, fileBuffer);
	// transform with hard code equation
	addr_in_hardcode = (BYTE*)((DWORD)EntryPoint - (DWORD)virtualAddress - 5);
	memcpy(startPoint + 14, &addr_in_hardcode, sizeof(DWORD));

	if (DEBUG) {
		printf("virtual address of jmp: %x, hard code: %x\n", virtualAddress, addr_in_hardcode);
	}

	// modify AddressOfEntryPoint to start point
	virtualAddress = FOAToVA(startPoint, fileBuffer);
	// minus ImageBase
	virtualAddress = (BYTE*)((DWORD)virtualAddress - pOptionalHeader->ImageBase);
	memcpy(&pOptionalHeader->AddressOfEntryPoint, &virtualAddress, sizeof(DWORD));

	if (DEBUG) {
		printf("virtual address of entry point: %x\n", virtualAddress);
	}

	ret = SaveBufferAsFile("msgBoxPad.exe", fileBuffer);

	free(fileBuffer);
}

void TEST_AddSectionToBuffer() {
	STATUS ret;
	PMEMORYBASE newFileBuffer;
	IMAGE_SECTION_HEADER* newSection;
	char name[SIZEOF_SECTION_NAME] = { 0x2e, 'b', 'c', 'b',
					'c'};

	// initialize global pointers
	fileBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();

	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00001000;
	
	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);
	ret = PEParser(newFileBuffer);
	printHeaders();

	ret = SaveBufferAsFile("notepad_ext.exe", newFileBuffer);
	free(fileBuffer);
	free(newFileBuffer);
}

void TEST_AddShellCodeToNewSection() {
	STATUS ret;
	PMEMORYBASE newFileBuffer;
	IMAGE_SECTION_HEADER* newSection;
	DWORD num_of_new_section = 0;
	char name[SIZEOF_SECTION_NAME] = { 0x2e, 'b', 'c', 'b',
					'c'};
	BYTE SHELL_CODE[] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
						  0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00,
						  0x00, 0x00 };
	BYTE* AddrOfMessageBox = (BYTE*)0x77D5050B;
	BYTE* startPoint = nullptr;
	BYTE* virtualAddress = nullptr;
	BYTE* addr_in_hardcode = nullptr;
	BYTE* EntryPoint;

	// initialize global pointers
	fileBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);

	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00001000;
	
	// add a new code section
	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);

	// save new buffer to global fileBuffer
	free(fileBuffer);
	fileBuffer = newFileBuffer;
	newFileBuffer = nullptr;
	ret = PEParser(fileBuffer);
	printHeaders();
	
	// TODO: add shell code to new section
	// copy shell code to new section
	// 6A 00 6A 00 6A 00 6A 00 E8 00 00 00 00 E9 00 00 00 00 
	num_of_new_section = pFileHeader->NumberOfSections - 1;
	startPoint = (BYTE*)((DWORD)fileBuffer + p_section_header[num_of_new_section].PointerToRawData);
	memcpy(startPoint, SHELL_CODE, sizeof(SHELL_CODE));

	// copy hard code of call address to memory space next to E8
	// 6A 00 6A 00 6A 00 6A 00 E8 FE D4 D3 76 E9 00 00 00 00 
	virtualAddress = FOAToVA(startPoint + 8, fileBuffer);
	addr_in_hardcode = (BYTE*)((DWORD)AddrOfMessageBox - (DWORD)virtualAddress - 5);
	memcpy(startPoint + 9, &addr_in_hardcode, sizeof(DWORD));
	
	// copy hard code of jmp address to memory space next to E9
	// 6A 00 6A 00 6A 00 6A 00 E8 FE D4 D3 76 E9 8B 43 FF FF 
	EntryPoint = (BYTE*)((DWORD)pOptionalHeader->ImageBase + (DWORD)pOptionalHeader->AddressOfEntryPoint);
	virtualAddress = FOAToVA(startPoint + 13, fileBuffer);
	addr_in_hardcode = (BYTE*)((DWORD)EntryPoint - (DWORD)virtualAddress - 5);
	memcpy(startPoint + 14, &addr_in_hardcode, sizeof(DWORD));

	// modify AddressOfEntryPoint to start point
	virtualAddress = FOAToVA(startPoint, fileBuffer);
	// minus ImageBase
	virtualAddress = (BYTE*)((DWORD)virtualAddress - pOptionalHeader->ImageBase);
	memcpy(&pOptionalHeader->AddressOfEntryPoint, &virtualAddress, sizeof(DWORD));


	ret = SaveBufferAsFile("notepad_injected.exe", fileBuffer);
	free(fileBuffer);
}

void TEST_ExtensionOfLastSection() {
	PMEMORYBASE newFileBuffer = nullptr;
	STATUS ret;

	// initialize global pointers
	fileBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	ret = ExtensionOfLastSection(fileBuffer, 0x1000, &newFileBuffer);
	
//	ret = SaveBufferAsFile("notepad_ext.exe", newFileBuffer);
	ret = PEParser(newFileBuffer);
	printHeaders();

	free(fileBuffer);
	free(newFileBuffer);
}

void TEST_MergingSections() {
	PMEMORYBASE newFileBuffer = nullptr;
	STATUS ret;

	// initialize global pointers
	fileBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();

	ret = MergingSections(fileBuffer, &newFileBuffer);
	
//	ret = SaveBufferAsFile("notepad_merge.exe", newFileBuffer);
	ret = PEParser(newFileBuffer);
	printHeaders();

	free(fileBuffer);
	free(newFileBuffer);
}

void TEST_SearchFuncAddrByName() {
	STATUS ret;
	PMEMORYBASE newFileBuffer = nullptr;

	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
	
	ret = PEReader("NONameDll.dll", &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	printExportDirectory();

	printf("Function Virtual Address: %x\n", SearchFuncAddrByName(fileBuffer, "Plus"));
}

void TEST_SearchFuncAddrByOrdinal() {
	STATUS ret;
	PMEMORYBASE newFileBuffer = nullptr;

	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
	
	ret = PEReader("NONameDLL.dll", &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	printExportDirectory();

	printf("Function Virtual Address: %x\n", SearchFuncAddrByOrdinal(fileBuffer, 13));
}

void TEST_MoveExportDirectoryToNewAddress() {
	STATUS ret;
	PMEMORYBASE newFileBuffer = nullptr;
	IMAGE_SECTION_HEADER* newSection;
	char name[SIZEOF_SECTION_NAME] = { 0x2e, 'e', 'd', 'a',
					't', 'a'};
	BYTE* location = nullptr;
	
	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	printExportDirectory();
	
	// prepare a new section
	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00001000;
	
	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);
	// relay to fileBuffer;
	free(fileBuffer);
	fileBuffer = newFileBuffer;
	newFileBuffer = nullptr;

	ret = PEParser(fileBuffer);
	location = (BYTE*)((DWORD)fileBuffer + p_section_header[pFileHeader->NumberOfSections - 1].PointerToRawData);
	ret = MoveExportDirectoryToNewAddress(location, fileBuffer);
	
	printHeaders();
	printExportDirectory();

	ret = SaveBufferAsFile("MoveExportDirectory.dll", fileBuffer);
	free(fileBuffer);
}

void TEST_MoveBaseRelocationTableToNewAddress() {
	STATUS ret;
	PMEMORYBASE newFileBuffer = nullptr;
	IMAGE_SECTION_HEADER* newSection;
	char name[SIZEOF_SECTION_NAME] = { 0x2e, 'e', 'd', 'a',
					't', 'a'};
	BYTE* location = nullptr;
	
	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);
	printHeaders();
	printBaseRelocationDirectory();

	// prepare a new section
	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00002000;
	newSection->Characteristics = 0x42000040;
	
	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);
	// relay to fileBuffer;
	free(fileBuffer);
	fileBuffer = newFileBuffer;
	newFileBuffer = nullptr;

	ret = PEParser(fileBuffer);
	location = (BYTE*)((DWORD)fileBuffer + p_section_header[pFileHeader->NumberOfSections - 1].PointerToRawData);
	ret = MoveBaseRelocationTableToNewAddress(location, fileBuffer);
	
	printHeaders();
	printBaseRelocationDirectory();

	printf("Total size of base relocation table: %x\n", ret);

//	ret = SaveBufferAsFile("MoveRelocationTable.dll", fileBuffer);

	free(fileBuffer);
}

void TEST_UpdateAddrWithBaseRelocationTable() {
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
	printBaseRelocationDirectory();

	ret = UpdateAddrWithBaseRelocationTable(fileBuffer, 0x11000000);
	
	ret = SaveBufferAsFile("MoveImageBase.dll", fileBuffer);
	
	free(fileBuffer);
}

void TEST_MoveImportDirectoryToNewAddress() {
	STATUS ret;
	IMAGE_SECTION_HEADER* newSection = nullptr;
	PMEMORYBASE newFileBuffer = nullptr;
	char* name = ".idata";
	BYTE* location = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* pDescriptor = nullptr;

	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader(FILE_IN, &fileBuffer);
	ret = PEParser(fileBuffer);

	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00003000;

	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);

	// relay to fileBuffer;
	free(fileBuffer);
	fileBuffer = newFileBuffer;
	newFileBuffer = nullptr;
	// fileBuffer has to be parsed once again, since fileBuffer has changed
	ret = PEParser(fileBuffer);

	if (DEBUG) {
		printf("TEST_MoveImportDirectoryToNewSection:\n");
		printf("Before moving:\n");
		printf("Original FOA of import directory: %x\n", (DWORD)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer));
		pDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer);
		printf("Addr of the first original thunk: %x\n", pDescriptor->OriginalFirstThunk);
	}	

	location = (BYTE*)((DWORD)fileBuffer + p_section_header[pFileHeader->NumberOfSections - 1].PointerToRawData);
	ret = MoveImportDirectoryToNewAddress(location, fileBuffer);
	
	if (DEBUG) {
		printf("After moving:\n");
		printf("new FOA of import directory: %x\n", (DWORD)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer));
		pDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer);
		printf("Addr of the first original thunk: %x\n", pDescriptor->OriginalFirstThunk);
		printf("\n");
	}

	printImportDirectory();

	// save as a file
	ret = SaveBufferAsFile("newNotepad.exe", fileBuffer);

	free(fileBuffer);
}

void TEST_AddNewImportDirectory() {
	STATUS ret;

	IMAGE_SECTION_HEADER* newSection = nullptr;
	PMEMORYBASE newFileBuffer = nullptr;
	char* name = ".idata";
	BYTE* location = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* pDescriptor = nullptr;

	size_t numOfFunctions = 1;
	IMAGE_IMPORT_DESCRIPTOR* newDirectory = nullptr;
	IMAGE_THUNK_DATA32* newLookupTable = nullptr;
	IMAGE_IMPORT_BY_NAME* newNameTable = nullptr;
	
	// Initialize global pointers
	fileBuffer = nullptr;
	imageBuffer = nullptr;
	pDosHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;

	ret = PEReader("notepad.exe", &fileBuffer);
	ret = PEParser(fileBuffer);

	printImportDirectory();
	
	// TODO: create a new section
	newSection = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSection->Name, name, SIZEOF_SECTION_NAME);
	newSection->Misc.PhysicalAddress = 0x00003000;
	
	ret = AddSectionToBuffer(fileBuffer, newSection, &newFileBuffer);
	// relay to fileBuffer;
	free(fileBuffer);
	fileBuffer = newFileBuffer;
	newFileBuffer = nullptr;
	// fileBuffer has to be parsed once again, since fileBuffer has changed
	ret = PEParser(fileBuffer);

//	printImportDirectory();

	// TODO: move import directory table to new section
	location = (BYTE*)((DWORD)fileBuffer + p_section_header[pFileHeader->NumberOfSections - 1].PointerToRawData);
	ret = MoveImportDirectoryToNewAddress(location, fileBuffer);

	// TODO: move new import table to new section
	// construct a descriptor: reserved end flag
	newDirectory = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
	memset(newDirectory, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
	newDirectory->ForwarderChain = 0;
	newDirectory->TimeDateStamp = 0;
	char* dllname = "DLLMethod.dll";
	
	// construct related table for case of 1 function
	// construct lookup table: reserved end flag
	newLookupTable = (IMAGE_THUNK_DATA32*)malloc(sizeof(IMAGE_THUNK_DATA32) * (numOfFunctions + 1));
	memset(newLookupTable, 0, sizeof(IMAGE_THUNK_DATA32) * (numOfFunctions + 1));
	newLookupTable->u1.Ordinal = 0x1;

	// construct name table (by ordinal by default): reserved end flag
	newNameTable = (IMAGE_IMPORT_BY_NAME*)malloc(sizeof(IMAGE_IMPORT_BY_NAME) * (numOfFunctions + 1));
	memset(newNameTable, 0, sizeof(IMAGE_IMPORT_BY_NAME) * (numOfFunctions + 1));
	newNameTable->Hint = 0;
	char* funcName = "myFunc";
	strcpy((char*)&newNameTable->Name, funcName);

	// find the end of descriptor and the location points to the beginning address of end flag 
	pDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)RVAToFOA((BYTE*)pDirectory[1].VirtualAddress, fileBuffer);
	while (pDescriptor->OriginalFirstThunk != 0) {
		pDescriptor++;
	}
	location = (BYTE*)pDescriptor;
	
	ret = AddNewImportDirectory(location, dllname, newDirectory, newLookupTable, newNameTable);
	
	printImportDirectory();
	// save as a file
	 ret = SaveBufferAsFile("notepad.inject.exe", fileBuffer);
	
	free(fileBuffer);
}

