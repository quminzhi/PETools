#include "Tools.h"

PMEMORYBASE fileBuffer;
PMEMORYBASE imageBuffer;

DOSHeader* pDosHeader;
FILEHeader* pFileHeader;
OPTIONALHeader* pOptionalHeader;
IMAGE_DATA_DIRECTORY* pDirectory;
IMAGE_EXPORT_DIRECTORY* pExportDirectory;
EXPORT_ADDRESS_TABLE* pAddressTable;
NAME_POINTER_TABLE* pNamePointerTable;
NAME_ORDINAL_TABLE* pNameOrdinalTable;
IMAGE_BASE_RELOCATION* pBaseRelocationBlock;
IMAGE_IMPORT_DESCRIPTOR* pImportDirectory;
IMAGE_IMPORT_BY_NAME* pNameTable;
IMAGE_THUNK_DATA32* pImportLookupTable;
IMAGE_THUNK_DATA32* pImportAddressTable;
IMAGE_BOUND_IMPORT_DESCRIPTOR* pBoundImportTable;
IMAGE_SECTION_HEADER* p_section_header;

int main(int argc, char* argv[]) {	
	TEST_FileOperation();
//	TEST_VAToFOA();
//	TEST_AddShellCodeToCodeSection();
//	TEST_AddSectionToBuffer();
//	TEST_AddShellCodeToNewSection();
//	TEST_ExtensionOfLastSection();
//	TEST_MergingSections();
//	TEST_SearchFuncAddrByName();
//	TEST_SearchFuncAddrByOrdinal();
//	TEST_MoveExportDirectoryToNewAddress();
//	TEST_MoveBaseRelocationTableToNewAddress();
//	TEST_UpdateAddrWithBaseRelocationTable();
//	TEST_PrintImportDirectoryTable();
//	TEST_PrintBoundImportDirectory();
//	TEST_MoveImportDirectoryToNewAddress();
//	TEST_AddNewImportDirectory();
	
	getchar();

	return 0;
}