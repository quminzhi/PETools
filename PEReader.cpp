// PEReader.cpp: implementation of the PEReader class.
//
//////////////////////////////////////////////////////////////////////

#include "PEReader.h"

STATUS PEReader(IN char* filename, OUT PFILEBASE* baseOfFileBuffer) {
	FILE *stream;
	size_t filesize = 0;
	int flag = 0;
	BYTE* fileBuffer = nullptr;
	
	if ((stream = fopen(filename, "rb")) != NULL) {
		// get file size
		fseek(stream, 0L, SEEK_END);
		filesize = ftell(stream);

		// reset stream pointer
		fseek(stream, 0L, SEEK_SET);

		// memory allocation and initialization
		fileBuffer = (BYTE*)malloc(sizeof(BYTE) * filesize);
		if (fileBuffer == nullptr) {
			printf("Memory allocate failed.\n");
			fclose(stream);
			return 255;
		}

		memset(fileBuffer, 0, sizeof(BYTE) * filesize);

		// memory read, fread returns the number of byte being read
		flag = fread(fileBuffer, sizeof(BYTE), filesize, stream);
		if (!flag) {
		    printf("Failed to read file.\n");
		    free(fileBuffer);
		    fclose(stream);
		    return 254;
		}
		
		fclose(stream);
		
		if (DEBUG) {
			printf("PEReader.PEReader:\n");
			printf("Filesize: %d\n", filesize);
			printf("fileBufferAddr: %x\n", fileBuffer);
			printf("\n");
		}
		
		*baseOfFileBuffer = fileBuffer;

		return 0;
	}
	else {
		printf("ERROR: The file was not opened properly.\n");
		return 253;
	}
}