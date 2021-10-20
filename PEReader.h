// PEReader.h: interface for the PEReader class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEREADER_H__25EF0264_3FD2_4C5A_9A8D_579AADD2FAD7__INCLUDED_)
#define AFX_PEREADER_H__25EF0264_3FD2_4C5A_9A8D_579AADD2FAD7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Global.h"
#include <stdio.h>
#include <stdlib.h> // for 'malloc'
#include <string.h> // for 'memset'

// PEReader:
//     read a file into memory in binary code, return status value.
// @filename: the name or path/name of input file
// @baseOfFileBuffer: an address of a pointer to file buffer
STATUS PEReader(IN char* filename, OUT PFILEBASE* baseOfFileBuffer);

#endif // !defined(AFX_PEREADER_H__25EF0264_3FD2_4C5A_9A8D_579AADD2FAD7__INCLUDED_)
