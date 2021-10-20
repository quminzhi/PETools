// Global.cpp: implementation of the Global class.
//
//////////////////////////////////////////////////////////////////////

#include "Global.h"

STATUS printInMemoryFormat(IN BYTE* addr, IN size_t size) {
	size_t i = 0;
	for (; i < size; i++) {
		printf("%02x ", addr[i]);
	}
	printf("\n");

	return 0;
}


int isInSection(int rva, int sec_begin, int sec_end) {
	if (rva >= sec_begin && rva <= sec_end) {
		return 1;
	}

	return 0;
}

BYTE* VAToFOA(IN BYTE* virtualAddress, IN BYTE* fileBase) {
	size_t i = 0;
	DWORD section_num = -1;
	DWORD rva = (DWORD)virtualAddress - pOptionalHeader->ImageBase;
	BYTE* fileOffsetAddress = nullptr;
	size_t number_of_sections = (size_t)pFileHeader->NumberOfSections;
	DWORD offset = 0;
	
	// if data is in header
	if (rva < p_section_header[0].VirtualAddress) {
		fileOffsetAddress = (BYTE*)((DWORD)fileBase + rva);
		return fileOffsetAddress; 
	}

	// check which section it belongs to
	for (; i < number_of_sections; i++) {
		if (isInSection(rva, p_section_header[i].VirtualAddress, p_section_header[i].VirtualAddress + p_section_header[i].SizeOfRawData)) {
			section_num = i;
			break;
		}
	}

	// error checking
	if (section_num == -1) {
		printf("Error: Data is not in legal range of any section.\n");
		exit(-1);
	}

	// calculate offset to the begin of section in image buffer
	offset = rva - p_section_header[section_num].VirtualAddress;

	// get the address of file buffer
	fileOffsetAddress = (BYTE*)((DWORD)fileBase + p_section_header[section_num].PointerToRawData + offset);

	return fileOffsetAddress;
}

BYTE* RVAToFOA(IN BYTE* relativeVirtualAddress, IN BYTE* fileBase) {
	size_t i = 0;
	DWORD section_num = -1;
	DWORD rva = (DWORD)relativeVirtualAddress;
	BYTE* fileOffsetAddress = nullptr;
	size_t number_of_sections = (size_t)pFileHeader->NumberOfSections;
	DWORD offset = 0;

	// if data is in header
	if (rva < p_section_header[0].VirtualAddress) {
		fileOffsetAddress = (BYTE*)((DWORD)fileBase + rva);
		return fileOffsetAddress;
	}

	// check which section it belongs to
	for (; i < number_of_sections; i++) {
		if (isInSection(rva, p_section_header[i].VirtualAddress, p_section_header[i].VirtualAddress + p_section_header[i].SizeOfRawData)) {
			section_num = i;
			break;
		}
	}

	// error checking
	if (section_num == -1) {
		printf("Error: Data is not in legal range of any section.\n");
		exit(-1);
	}

	// calculate offset to the begin of section in image buffer
	offset = rva - p_section_header[section_num].VirtualAddress;

	// get the address of file buffer
	fileOffsetAddress = (BYTE*)((DWORD)fileBase + p_section_header[section_num].PointerToRawData + offset);

	return fileOffsetAddress;
}

BYTE* FOAToVA(IN BYTE* fileOffsetAddress, IN BYTE* fileBase) {
	size_t i;
	DWORD section_num = -1;
	DWORD file_offset = (DWORD)fileOffsetAddress - (DWORD)fileBase;
	BYTE* virtualAddress = nullptr;
		
	size_t number_of_sections = (size_t)pFileHeader->NumberOfSections;
	DWORD offset = 0;

	if (file_offset < p_section_header[0].PointerToRawData) {
		virtualAddress = (BYTE*)((DWORD)pOptionalHeader->ImageBase + file_offset);
		return virtualAddress;
	}

	// check which section it belongs to
	for (i = 0; i < number_of_sections; i++) {
		if (isInSection(file_offset, p_section_header[i].PointerToRawData, p_section_header[i].PointerToRawData + p_section_header[i].SizeOfRawData)) {
			section_num = i;
			break;
		}
	}

	// error checking
	if (section_num == -1) {
		printf("Error: Data is not in legal range of any section.\n");
		exit(-1);
	}
	
	// calculate offset to the begin of section in file buffer
	offset = file_offset - p_section_header[section_num].PointerToRawData;

	// get virtual address
	virtualAddress = (BYTE*)((DWORD)pOptionalHeader->ImageBase + p_section_header[section_num].VirtualAddress + offset);

	return virtualAddress;
}


BYTE* FOAToRVA(IN BYTE* fileOffsetAddress, IN BYTE* fileBase) {
	size_t i;
	DWORD section_num = -1;
	DWORD file_offset = (DWORD)fileOffsetAddress - (DWORD)fileBase;
	BYTE* relativeVirtualAddress = nullptr;
		
	size_t number_of_sections = (size_t)pFileHeader->NumberOfSections;
	DWORD offset = 0;

	if (file_offset < p_section_header[0].PointerToRawData) {
		relativeVirtualAddress = (BYTE*)file_offset;
		return relativeVirtualAddress;
	}

	// check which section it belongs to
	for (i = 0; i < number_of_sections; i++) {
		if (isInSection(file_offset, p_section_header[i].PointerToRawData, p_section_header[i].PointerToRawData + p_section_header[i].SizeOfRawData)) {
			section_num = i;
			break;
		}
	}

	// error checking
	if (section_num == -1) {
		printf("Error: Data is not in legal range of any section.\n");
		exit(-1);
	}
	
	// calculate offset to the begin of section in file buffer
	offset = file_offset - p_section_header[section_num].PointerToRawData;

	// get virtual address
	relativeVirtualAddress = (BYTE*)((DWORD)p_section_header[section_num].VirtualAddress + offset);

	return relativeVirtualAddress;
}
