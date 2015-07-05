/*
Shim Process Scanner
Windows x64 Process Scanner to detect application compatibility shims

Author:		Sean Pierce
Email:		sdb@securesean.com
Date:		July 1st 2015

Compile Notes:
Make sure the target is x64. In this solution file I ported all the Win32 settings to x64 then simply renamed it.

This is proof-of-concept code so I did a lot of unnecessary things, and this was a learning project for me;
especially when dealing with undocumented structs, and programming for x64. I apologize for:
-The commented out code
-The mixed conventions
-Inefficienct code

Want to add:
cmd parameters for scanning a spefic process, showing debugging, verbose, etc
continious scan?
*/

#define _CRT_RAND_S
#define MAX_UNICODE_PATH 32767

// from MSDN - pretty useful
#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer } 

#include<stdio.h>
#include<Windows.h>
#include"Winternl.h"
#include<stddef.h>
#include<inttypes.h>
#include"scanner.h"
#include<Ntstatus.h>
#include<TlHelp32.h>
#include<stdlib.h>
#include<shlwapi.h> // for PathStripPath 
#pragma comment(lib, "shlwapi.lib")

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL SetDebugPrivilege();
BOOL wideStringReplace(PWSTR target, PWSTR findText, PWSTR insertText);
BOOL unicodeStringReplace_bugged(PUNICODE_STRING target, PUNICODE_STRING findText, PUNICODE_STRING insertText);
BOOL unicodeStringMatch_ignoreDllCase_old(PUNICODE_STRING str1, PUNICODE_STRING str2);
BOOL unicodeStringMatch(PUNICODE_STRING str1, PUNICODE_STRING str2);
BOOL checkForKnownACdlls(PUNICODE_STRING fullDllName);
BOOL pebHasAppCompatDlls_old(P_moonsols_win7_PEB peb_r);
BOOL pebHasAppCompatFlags(P_moonsols_win7_PEB peb);
char * getFileName(char * fullPath);

// TODO: make these command line arguement options
BOOL debug = FALSE;
BOOL verbose = TRUE;
BOOL veryVerbose = FALSE;

BOOL debuggingRemotePEBproblem = FALSE;
BOOL debuggingStringOpProblem = FALSE;

typedef HMODULE(WINAPI * pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
//NTSTATUS

// AdjustTokenPrivilege sample code
BOOL SetPrivilege(HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
	)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		DWORD err = GetLastError();
		printf("LookupPrivilegeValue error: %u\n", err);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		DWORD err = GetLastError();
		printf("warning: AdjustTokenPrivileges error: %u\n", err);
		return FALSE;
	}

	return TRUE;
}

BOOL SetDebugPrivilege()
{
	HANDLE hToken;
	BOOL ret;
	try
	{
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
		ret = SetPrivilege(hToken, SE_DEBUG_NAME, 1);
	}
	catch (char * str)
	{
		fprintf(stderr, "doSetDebugPrivilege: failed: %s\n", str);
		exit(EXIT_FAILURE);
	}
	return ret;
}

BOOL unicodeCopyString(PUNICODE_STRING from, PUNICODE_STRING to)
{
	// I'm not putting up with malformed structs
	if (from->MaximumLength < to->MaximumLength ||
		from->MaximumLength < to->MaximumLength ||
		from->MaximumLength < to->MaximumLength)
	{
		return FALSE;
	}
	else if (from->Length == 0 || to->Length == 0)
	{
		return TRUE;
	}

	int i = 0;
	for (i = 0; i < from->Length; i++)
	{
		to->Buffer[i] = from->Buffer[i];
	}

	return TRUE;
}

BOOL wideStringReplace(PWSTR target, PWSTR findText, PWSTR insertText){
	if (target == NULL || findText == NULL || insertText == NULL)
	{
		if (debuggingStringOpProblem)
			printf("One or more of the string pointers are invalid\n");
		return FALSE;
	}

	unsigned int findTextLength = 0;
	while (findText[findTextLength] != NULL)
		findTextLength++;

	BOOL foundFlag = TRUE;
	unsigned int i, j, offset = 0;
	for (i = 0; target[i] != NULL; i++)
	{
		// search
		if (target[i] == findText[0])
		{
			if (debuggingStringOpProblem)
				printf("First letter found: %c\n", target[i]);
			foundFlag = TRUE;
			offset = 0;
			while (findText[offset] != NULL)
			{
				if (target[i + offset] != findText[offset])
				{
					if (debuggingStringOpProblem)
						printf("Next letter not found: '%c' vs. '%c'   Breaking...\n", target[i + offset], findText[offset]);
					foundFlag = FALSE;
					break;
				}
				offset++;

				//if (target[i + offset] == NULL && debug)
				//	printf("Ran out of string on target... checking if same for findText...\n");

				if (target[i + offset] == NULL && findText[offset] != NULL)
				{
					if (debuggingStringOpProblem)
						printf("\tYup.. Ran out of string on target and not the findText.. breaking\n");
					foundFlag = FALSE;
					break;
				} // end test of end of string

			} // end compare the rest of the letters

			// REPLACE
			if (foundFlag)
			{
				for (j = 0; insertText[j] != NULL; j++)
				{
					if (debuggingStringOpProblem)
						printf("Replaced '%c' with '%c'\n", target[i + j], insertText[j]);
					target[i + j] = insertText[j];
				}
			}
		} // end compare first char
	}// end for/while

	return TRUE;
}

BOOL unicodeStringReplace_bugged(PUNICODE_STRING target, PUNICODE_STRING findText, PUNICODE_STRING insertText){
	// I'm not putting up with malformed structs
	if (target->MaximumLength < target->Length ||
		findText->MaximumLength < findText->Length ||
		insertText->MaximumLength < insertText->Length)
	{
		return FALSE;
	}
	// basic checks
	else if (target->Length == 0 || findText->Length == 0 || insertText->Length == 0){
		//fprintf(stderr, "Unicode String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("One of the unicode string's are of length 0\n");
		return FALSE;
	}
	else if (target->MaximumLength < findText->MaximumLength || target->MaximumLength < insertText->Length){
		//fprintf(stderr, "Unicode MAX String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("The target cannot handle either the findText or the insertText\n");
		return FALSE;
	}

	unsigned int i, offset = 0;
	BOOL foundSubString = TRUE;
	for (i = 0; i < target->Length; i++){

		// first letter match
		if (target->Buffer[i] == findText->Buffer[0]){

			// FIND
			// check the rest of the characters
			for (offset = 0; offset < findText->Length &&
				(i + offset) < target->Length &&
				(i + offset) < target->MaximumLength; // redundunte check, but better safe than sorry
			offset++)
			{
				if (target->Buffer[i + offset] != findText->Buffer[offset]){ // no match
					foundSubString = FALSE;
					break;
				}// end break case
			}// end for each character

			// REPLACE
			//if (offset == findText->Length){	// the length doesn't match for some reason
			if (foundSubString){
				for (offset = 0; offset < findText->Length &&
					(i + offset) < target->Length &&			// redundunte check, but better safe than sorry
					(i + offset) < target->MaximumLength;		// redundunte check, but better safe than sorry
				offset++)
				{
					target->Buffer[i + offset] = findText->Buffer[offset];
				}
				return TRUE;
			}
			// reset flag
			foundSubString = TRUE;

		}// end check on first character
	}// end of for each character
	return FALSE;
}

// returns a new ascii string with only the file created from the full path
// reimplement these later to prevent hooking
char * getFileName(char * fullPath)
{
	//printf("\t\tFullpath: %s\n", fullPath);
	char * filename = (char *)malloc(MAX_PATH);
	ZeroMemory(filename, MAX_PATH);

	strcpy_s(filename, MAX_PATH, fullPath);
	//printf("\t\tCopy of Fullpath: %s\n", filename);
	// FltParseFileName() would be nice for unicode
	PathStripPath(filename);

	//printf("\t\tFile: %s\n", filename);
	return filename;
}


// sometimes the full dll name ends with a '.DLL' instead of the real file extention '.dll'
// so this function makes upper case versions of the strings
BOOL unicodeStringMatch_ignoreDllCase_old(UNICODE_STRING str1, UNICODE_STRING str2){
	if (str1.Buffer == NULL || str2.Buffer == NULL)
	{
		if (debug)
		{
			printf("ERROR: unicodeStringMatch_ignoreDllCase One or both strings to be compared were NULL\n");
		}
		return FALSE;
	}


	BOOL result = FALSE;
	// NOTE: This works because '.dll' and .DLL' are always at the end of a null string
	DECLARE_CONST_UNICODE_STRING(lowerCasedll, L".dll");
	DECLARE_CONST_UNICODE_STRING(upperCaseDLL, L".DLL");

	// declare these values locally because I can't malloc for some reason
	UNICODE_STRING str1_upperDLL;
	PWSTR str1_upperDLL_buffer[MAX_UNICODE_PATH];
	str1_upperDLL.Buffer = (PWSTR)str1_upperDLL_buffer;

	UNICODE_STRING str2_upperDLL;
	PWSTR str2_upperDLL_buffer[MAX_UNICODE_PATH];
	str2_upperDLL.Buffer = (PWSTR)str2_upperDLL_buffer;


	// set the first string
	str1_upperDLL.Length = str1.Length;
	str1_upperDLL.MaximumLength = str1.MaximumLength;
	// copy the string
	unicodeCopyString(&str1, &str1_upperDLL);
	// change the '.dll' to '.DLL' in the new string
	//if (unicodeStringReplace(&str1_upperDLL, &lowerCasedll, &upperCaseDLL) && debug){
	if (wideStringReplace(str1_upperDLL.Buffer, lowerCasedll.Buffer, upperCaseDLL.Buffer) && debuggingStringOpProblem){
		printf("Changed: %wZ  to  %wZ\n", str1, str1_upperDLL);
	}

	// set the second string
	str2_upperDLL.Length = str1.Length;
	str2_upperDLL.MaximumLength = str1.MaximumLength;
	// copy the string
	unicodeCopyString(&str2, &str2_upperDLL);
	// change the '.dll' to '.DLL' in the new string
	if (wideStringReplace(str1_upperDLL.Buffer, lowerCasedll.Buffer, upperCaseDLL.Buffer) && debuggingStringOpProblem){
		printf("Changed: %wZ  to  %wZ\n", str1, str1_upperDLL);
	}


	/*
	// get memory for unicode struct
	PUNICODE_STRING str1_upperDLL = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	// get memory for the unicode string
	str1_upperDLL->Buffer = (PWSTR)malloc(sizeof(UNICODE_STRING));
	// set the first string
	str1_upperDLL->Length = str1.Length;
	str1_upperDLL->MaximumLength = str1.MaximumLength;
	// copy the string
	unicodeCopyString(&str1, str1_upperDLL);
	// change the '.dll' to '.DLL' in the new string
	if (unicodeStringReplace(str1_upperDLL, &lowerCasedll, &upperCaseDLL) && debug){
	printf("Changed: %wZ  to  %wZ\n", str1, *str1_upperDLL);
	}


	HANDLE heapHandle = GetProcessHeap();
	if (heapHandle == NULL){
	printf("Error: Could not get heap. Error code: 0x%x\n", GetLastError());
	}
	// don't know why these keep failing
	//PUNICODE_STRING str2_upperDLL = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	//str2_upperDLL->Buffer = (PWSTR)malloc(sizeof(UNICODE_STRING));	// that's why
	HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING));

	return FALSE;
	printf("I allociated!\n");
	PUNICODE_STRING str2_upperDLL = (PUNICODE_STRING)HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING));
	str2_upperDLL->Buffer = (PWSTR)malloc(sizeof(UNICODE_STRING));
	// set the second string
	str2_upperDLL->Length = str2.Length;
	str2_upperDLL->MaximumLength = str2.MaximumLength;

	unicodeCopyString(&str2, str2_upperDLL);
	// change the '.dll' to '.DLL' in the new string
	if (unicodeStringReplace(str2_upperDLL, &lowerCasedll, &upperCaseDLL) && debug){
	printf("Changed: %wZ  to  %wZ\n", str2, *str2_upperDLL);
	}
	*/

	BOOL restult = unicodeStringMatch(&str1_upperDLL, &str2_upperDLL);
	return result;
}

// I make my own functions so I don't have to call API's that could be hooked
BOOL unicodeStringMatch(PUNICODE_STRING str1, PUNICODE_STRING str2){

	// I'm not putting up with malformed structs
	if (str1->MaximumLength < str1->Length ||
		str2->MaximumLength < str2->Length)
	{
		return FALSE;
	}
	// basic checks
	else if (str1->Length == str2->Length && str1->Length == 0){
		//fprintf(stderr, "Unicode String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("Unicode String lengths are 0\n");
		return TRUE;
	}
	else if (str1->MaximumLength == str2->MaximumLength && str1->MaximumLength == 0){
		//fprintf(stderr, "Unicode MAX String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("Unicode MAX String lengths are 0\n");
		return TRUE;
	}
	else if (str1->Length == 0 || str2->Length == 0){
		if (debuggingStringOpProblem)
			printf("One of string lengths is 0 and the other is not.\n");
		return FALSE;
	}


	USHORT i = 0;
	for (i = 0;
		i < str1->Length &&
		i < str2->Length &&
		i < str1->MaximumLength &&
		i < str2->MaximumLength;
	i++)
	{
		// I'm basically assuming they are unmutable null terminated strings
		// current char check
		if (str1->Buffer[i] != str2->Buffer[i])
		{
			return FALSE;
		}

		/*
		if (i != 0 && // short circuit for testing the
		str1->Buffer[i - 1] == str2->Buffer[i - 1])
		{

		}*/


	}

	printf("Warning: %wZ was found!\n", str1);
	//if (verbose || veryVerbose || debuggingStringOpProblem || debug){
	//printf("Warning: %wZ was found!\n", str1);

	/*
	if (i != str1->Length && i != str2->Length){
	printf("The counter was %d str1 length was %d and str 2 was %d \n", i, str1->Length, str2->Length);
	}*/

	//}
	return TRUE;
}

BOOL unicodeStringMatch_ignoreCase(PUNICODE_STRING str1, PUNICODE_STRING str2){
	unsigned char char1Upper = 0;
	unsigned char char2Upper = 0;
	if (debuggingStringOpProblem){
		printf("\t\tComparing Executables: '%wZ' vs. '%wZ'\n", str1, str2);
	}

	// I'm not putting up with malformed structs
	if (str1->MaximumLength < str1->Length ||
		str2->MaximumLength < str2->Length)
	{
		return FALSE;
	}
	// basic checks
	else if (str1->Length == str2->Length && str1->Length == 0){
		//fprintf(stderr, "Unicode String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("Unicode String lengths are 0\n");
		return TRUE;
	}
	else if (str1->MaximumLength == str2->MaximumLength && str1->MaximumLength == 0){
		//fprintf(stderr, "Unicode MAX String lengths are 0\n");
		if (debuggingStringOpProblem)
			printf("Unicode MAX String lengths are 0\n");
		return TRUE;
	}
	else if (str1->Length == 0 || str2->Length == 0){
		if (debuggingStringOpProblem)
			printf("One of string lengths is 0 and the other is not.\n");
		return FALSE;
	}


	USHORT i = 0;

	for (i = 0;
		i < (str1->Length / 2) &&
		i < (str2->Length / 2) &&	// Length / 2 is becuase 'Length' is in bytes but 'Buffer' is a wide char string (aka 2 bytes)
		i < str1->MaximumLength &&
		i < str2->MaximumLength;
	i++)
	{
		// I'm basically assuming they are unmutable null terminated strings
		// current char check

		// make the strings lower case by checking A to Z. If it is, then add 0x20 to make it a to z
		if ((str1->Buffer[i] >= 0x41) && ((str1->Buffer[i] <= 0x5A)))
		{
			char1Upper = (0x20) | (str1->Buffer[i]);
		}
		else{
			char1Upper = str1->Buffer[i];
		}

		// make the strings lower case by checking A to Z. If it is, then add 0x20 to make it a to z
		if ((str2->Buffer[i] >= 0x41) && ((str2->Buffer[i] <= 0x5A)))
		{
			char2Upper = 0x20 | str2->Buffer[i];
		}
		else{
			char2Upper = str2->Buffer[i];
		}


		if (char1Upper != char2Upper)
		{
			if (debuggingStringOpProblem) {
				printf("\t\t\tFailed in Comparing %#x ('%c') to %#x ('%c')\n", char1Upper, char1Upper, char2Upper, char2Upper);
			}
			return FALSE;
		}


	}

	if (verbose || debuggingStringOpProblem || debug){
		printf("Warning: '%wZ' was found!\n", str2);
		/*
		if (i != str1->Length && i != str2->Length){
		printf("The counter was %d str1 length was %d and str 2 was %d \n", i, str1->Length, str2->Length);
		}
		*/
	}
	return TRUE;
}


// change an ascii string to a unicode string struct
PUNICODE_STRING unicodeStringFromCharArray(char * charString)
{
	unsigned int lengthWithoutNulls = 0;
	PUNICODE_STRING newString = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	ZeroMemory(newString, sizeof(UNICODE_STRING));
	//printf("\t\tIncomming char String: %s from %#p\n", charString, charString);

	while (charString[lengthWithoutNulls] != 0 && lengthWithoutNulls < MAX_PATH){
		lengthWithoutNulls++;
	}

	if (lengthWithoutNulls == MAX_PATH && debug)
	{
		printf("WARNING: String is max size. Probably bad string (or not NULL terminated): '%s'\n", charString);
	}
	else if (lengthWithoutNulls == 0){
		newString->Length = 0;
		newString->MaximumLength = 1;
		PWSTR  Buffer = (PWSTR)malloc(1);
		Buffer[0] = 0;
		newString->Buffer = Buffer;

		return newString;
	}

	// make new unicode string struct
	newString->Length = (lengthWithoutNulls * 2);
	newString->MaximumLength = lengthWithoutNulls * 2;
	PWSTR  Buffer = (PWSTR)malloc(lengthWithoutNulls * 2);
	ZeroMemory(Buffer, lengthWithoutNulls * 2); // I shouldn't actually need this but just to be safe...
	newString->Buffer = Buffer;

	// actually copy the string - assuming UTF-8
	// I shouldn't actually need all these conditions but just to be safe...
	unsigned int i = 0;
	//printf("\t\tAbout to populate UNICODE_STRING String: '%wZ' at address %#p\n", newString, &(newString->Buffer));
	while (i < lengthWithoutNulls && i < MAX_PATH){
		newString->Buffer[i] = charString[i];		//Buffer[i] doesn't need to be Buffer[i * 2] because Buffer is a wide string
		i++;
	}
	//printf("\t\tReturning UNICODE_STRING String: '%wZ' at address %#p\n", newString, &(newString->Buffer));
	return newString;
}


// I know this is stupid inefficient
BOOL checkForKnownACdlls(PUNICODE_STRING fullDllName){
	//printf("\t\tComparing Executable: '%wZ'\n", fullDllName);

	// commented out DLL names are listed somewhere previously
	BOOL result = FALSE;

	// xp x86
	DECLARE_CONST_UNICODE_STRING(acAdproc_UnicodeStruct, L"acadproc.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acAdproc_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acgeneral_UnicodeStruct, L"acgenral.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acgeneral_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(aclayers_UnicodeStruct, L"aclayers.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &aclayers_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(aclua_UnicodeStruct, L"aclua.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &aclua_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acspecfc_UnicodeStruct, L"acspecfc.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acspecfc_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acxtrnal_UnicodeStruct, L"acxtrnal.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acxtrnal_UnicodeStruct);

	// win 2003 x86
	//DECLARE_CONST_UNICODE_STRING(acLayers_UnicodeStruct, L"AcLayers.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acLayers_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acRes_UnicodeStruct, L"AcRes.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acRes_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acWow_UnicodeStruct, L"acwow64.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWow_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acXtrnal_UnicodeStruct, L"AcXtrnal.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acXtrnal_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(ScShim_UnicodeStruct, L"SCShim.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &ScShim_UnicodeStruct);

	// win 2003 x64

	// win 2003 R2 x64

	// win 2008 x64

	// win 2008 R2 x64

	// vista x86

	// vista x64

	// win 7 x86

	// win 7 x64
	DECLARE_CONST_UNICODE_STRING(acApphelp_UnicodeStruct, L"apphelp.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acApphelp_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acGeneral_UnicodeStruct, L"AcGenral.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acGeneral_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acLayers_UnicodeStruct, L"AcLayers.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acLayers_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acRes_UnicodeStruct, L"AcRes.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acRes_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acSpecfc_UnicodeStruct, L"AcSpecfc.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acSpecfc_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acWow_UnicodeStruct, L"acwow64.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWow_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(acXtrnal_UnicodeStruct, L"AcXtrnal.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acXtrnal_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(apiHex_UnicodeStruct, L"apihex86.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &apiHex_UnicodeStruct);

	// added win 8 x86
	DECLARE_CONST_UNICODE_STRING(acWinRT_UnicodeStruct, L"AcWinRT.dll");
	result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWinRT_UnicodeStruct);


	// win 8 x64

	// win 10 x64

	// win 2012 x64

	// win 2012 r2 x64 
	//DECLARE_CONST_UNICODE_STRING(acGeneral_UnicodeStruct, L"AcGenral.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acGeneral_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acGeneral_UnicodeStruct, L"AcLayers.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acGeneral_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acspecfc_UnicodeStruct, L"acspecfc.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acspecfc_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acWinRT_UnicodeStruct, L"AcWinRT.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWinRT_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acXtrnal_UnicodeStruct, L"AcXtrnal.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acXtrnal_UnicodeStruct);





	// win 2012 r2 apppatch64 x64 
	//DECLARE_CONST_UNICODE_STRING(acRes_UnicodeStruct, L"AcRes.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acRes_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acspecfc_UnicodeStruct, L"AcSpecfc.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acspecfc_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acWinRT_UnicodeStruct, L"AcWinRT.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWinRT_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acWow_UnicodeStruct, L"acwow64.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acWow_UnicodeStruct);

	//DECLARE_CONST_UNICODE_STRING(acXtrnal_UnicodeStruct, L"AcXtrnal.dll");
	//result = result | unicodeStringMatch_ignoreCase(fullDllName, &acXtrnal_UnicodeStruct);


	// known malicious
	DECLARE_CONST_UNICODE_STRING(roamingTiger_UnicodeStruct, L"AcProtect.dll");
	result = result | unicodeStringMatch(fullDllName, &roamingTiger_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(searchProtect_1_UnicodeStruct, L"vc32loader.dll");
	result = result | unicodeStringMatch(fullDllName, &searchProtect_1_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(searchProtect_2_UnicodeStruct, L"VCLdr64.dll");
	result = result | unicodeStringMatch(fullDllName, &searchProtect_2_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(searchProtect_3_UnicodeStruct, L"SPVCLdr64.dll");
	result = result | unicodeStringMatch(fullDllName, &searchProtect_3_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(searchProtect_4_UnicodeStruct, L"SPVC64Loader.dll");
	result = result | unicodeStringMatch(fullDllName, &searchProtect_4_UnicodeStruct);

	DECLARE_CONST_UNICODE_STRING(searchProtect_5_UnicodeStruct, L"spvc64loader.dll");
	result = result | unicodeStringMatch(fullDllName, &searchProtect_5_UnicodeStruct);




	//if (unicodeStringMatch(fullDllName, acGeneral_UnicodeStruct))
	//	printf("Warning: %wZ was found!\n", fullDllName);


	// future: look in the %windir%\AppPatch and if any of those dll's are loaded into the other processes... alert

	return result;
}


BOOL pebHasAppCompatDlls_old(P_moonsols_win7_PEB peb_r){
	printf("\tPEB Address: 0x%p\n", &peb_r);
	BOOL result = FALSE;

	if (debug)
		printf("******Trying the (mostly) documented way (InMemoryOrder List) ******\n");
	PPEB peb = (PPEB)peb_r;
	PPEB_LDR_DATA ldr = peb->Ldr;
	LIST_ENTRY *list = (ldr->InMemoryOrderModuleList.Flink);
	LDR_DATA_TABLE_ENTRY *ldr_ent = ldr_ent = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	int i = 0;
	while (ldr_ent){

		ldr_ent = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		//printf("ldr_ent is 0x%p", ldr_ent);
		if (ldr_ent->DllBase == NULL)break;

		if (debug){
			printf("This Table Entry: %p\n", ldr_ent);
			printf("DLL Name: %wZ\n", ldr_ent->FullDllName);
		}
		//printf("\tChecking DLL Name: %wZ\n", ldr_ent->FullDllName);
		result = result | checkForKnownACdlls(&(ldr_ent->FullDllName));

		list = ldr_ent->InMemoryOrderLinks.Flink;

		i++;
	}
	if (debug)
		printf("Total Module Count: %d\n", i);

	// slightly easier because the InLoadOrder list is the first members in the struct so the same ListEntry pointers can be cast as LDR DATA TABLE

	if (debug)
		printf("\n******Trying the undocumented way (InLoadOrder List) ******\n");
	i = 0;
	P_moonsols_win7_PEB_LDR_DATA ldr_r = peb_r->Ldr;
	P_moonsols_LDR_DATA_TABLE_ENTRY ldrTableEntry_r = (P_moonsols_LDR_DATA_TABLE_ENTRY)ldr_r->InLoadOrderModuleList.Flink;
	P_moonsols_LDR_DATA_TABLE_ENTRY firstModule = ldrTableEntry_r;
	do{
		if (debug){
			printf("This Table Entry:\t0x%p\n", ldrTableEntry_r);
			printf("DLL Name: %wZ\n", ldrTableEntry_r->FullDllName);
			printf("Next Link_r:     \t0x%p\n", ldrTableEntry_r->InLoadOrderLinks.Flink);
		}
		//if (ldrTableEntry_r->DllBase == NULL)break;

		result = result || checkForKnownACdlls(&(ldrTableEntry_r->FullDllName));
		ldrTableEntry_r = (P_moonsols_LDR_DATA_TABLE_ENTRY)ldrTableEntry_r->InLoadOrderLinks.Flink;

		if (i++ > 1088){
			//"The maximum number of indexes per process is 1,088."
			printf("WARNING. Had to break from linked list forcefully\n");
			break;
		}

	} while (ldrTableEntry_r && ldrTableEntry_r != firstModule);
	if (debug)
		printf("Total Module Count: %d\n", i);

	return result;
}


// I'm not using this function for remotely copied over PEB's due to a casting issue (I think)
BOOL pebHasAppCompatFlags(P_moonsols_win7_PEB peb){

	if (verbose){
		printf("Address of PEB: 0x%#016p\n", peb);

		size_t SessionId_offset = offsetof(moonsols_win7_PEB, SessionId);
		printf("SessionID's Offset is: 0x%x\n", SessionId_offset);	// suppose to be 0x2c0 for x64 win7
		printf("SessionID Supposed 2b: 0x2c0\n", SessionId_offset);

		//unsigned char * SessionId = (unsigned char *)(&peb + 0x000000002c0);
		unsigned char SessionId = peb->SessionId;
		printf("SessionID: %x\n", SessionId);

		size_t AppCompatFlags_offset = offsetof(moonsols_win7_PEB, AppCompatFlags);
		printf("AppCompatFlags's Offset is: 0x%x\n", AppCompatFlags_offset);	// suppose to be 0x2c0 for x64 win7
		printf("AppCompatFlags Supposed 2b: 0x2c8\n");

		//printf("Address of AppCompatFlag 0x%016p\n", &peb->AppCompatFlags);
		printf("Address of AppCompatFlag Low %#p has value %#x\n", &peb->AppCompatFlags.LowPart, peb->AppCompatFlags.LowPart);
		printf("Address of AppCompatFlag High %#p has value %#x\n", &peb->AppCompatFlags.HighPart, peb->AppCompatFlags.HighPart);
		printf("Address of AppCompatFlagsUser Low %#p has value %#x\n", &peb->AppCompatFlagsUser.LowPart, peb->AppCompatFlagsUser.LowPart);
		printf("Address of AppCompatFlagsUser High %#p has value %#x\n", &peb->AppCompatFlagsUser.HighPart, peb->AppCompatFlagsUser.HighPart);
		printf("Address of ShimData Pointer %#p has value %#x\n", &peb->pShimData, peb->pShimData);
		printf("Address of AppCompatInfo Pointer %#p has value %#x\n", &peb->AppCompatInfo, peb->AppCompatInfo);
	}


	if (
		peb->AppCompatFlags.LowPart == 0 &&
		peb->AppCompatFlags.HighPart == 0 &&
		peb->AppCompatFlagsUser.LowPart == 0 &&
		peb->AppCompatFlagsUser.HighPart == 0 &&
		peb->pShimData == 0 &&
		peb->AppCompatInfo == 0){
		if (veryVerbose || debug)
			printf("\tAll flags False. No Shim flags detected\n", peb);

		return FALSE;
	}
	else{
		printf("*****************************************************\n\n");
		printf("\tShim detected! One or more flags set!\n", peb);
		// collect and read off memory values
		printf("\tAppCompatFlag %#x\n", peb->AppCompatFlags);
		printf("\tAppCompatFlag Low %#x\n", peb->AppCompatFlags.LowPart);
		printf("\tAppCompatFlag High %#x\n", peb->AppCompatFlags.HighPart);
		printf("\tAppCompatFlagsUser Low %#x\n", peb->AppCompatFlagsUser.LowPart);
		printf("\tAppCompatFlagsUser High %#x\n", peb->AppCompatFlagsUser.HighPart);
		printf("\tShimData Pointer %#p\n", peb->pShimData);
		printf("\tAppCompatInfo Pointer %#p\n", peb->AppCompatInfo);
		printf("*****************************************************\n\n");
		return TRUE;
	}
}

int readRemoteProcessForShims(PROCESSENTRY32 pe32, PROCESS_INFORMATION pi, WORD remote32bitPEBAddress){
	// normally I wouldn't pass the whole struct in, but I don't really need to pass anything back and I don't feel like re-writing code

	//PROCESS_INFORMATION pi = { 0 };
	//PROCESSENTRY32 pe32

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	NTSTATUS status;

	// Setup for loop
	HMODULE ntdll = LoadLibrary("Ntdll.dll");
	// Dyamic calling to (attempt) prevention of defaul shim style hooking
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

	ULONG pbi_len = 0;
	NTSTATUS result = (NTSTATUS)NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &pbi_len);

	BOOL pebResult = FALSE;
	BOOL DllResult = FALSE;
	BOOL DllResultTemp = FALSE;

	SIZE_T bytes_read = 0;
	SIZE_T bytes_read_for_undocumented_remote_peb = 0;

	char * exePath;
	if (result == 0)
	{
		// this will only show the x64 DLLs
		if (pbi.PebBaseAddress)	// read about how this works because I don't think it's getting the right PEB, it's not the 32 bit or 64 bit... maybe I'll need to get the context struct to get the PEB address from the register. Look to see how process explorer and/or process hacker does it
		{
			moonsols_win7_PEB undocumented_remote_peb = { 0 };						// undocumented
			_PEB remote_peb = { 0 };									// documented
			//P_moonsols_win7_PEB_LDR_DATA pLdr = { 0 };				// undocumented
			PPEB_LDR_DATA pLdr = { 0 };									// documented
			_moonsols_win7_PEB_LDR_DATA LdrData = { 0 };				// undocumented
			//PEB_LDR_DATA LdrData = { 0 };								// documented

			bytes_read = 0;
			if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &remote_peb, sizeof(_PEB), &bytes_read))
			{

				if (debug) printf("PEB Address in %s: %#p\n", pe32.szExeFile, pbi.PebBaseAddress);
				if (debuggingRemotePEBproblem) printf("The PEB address (according to NtQueryInformationProcess) is at address: %#p\n", pbi.PebBaseAddress);
				// I need the undocumented fields so I'm using a undocument struct re-created from windbg
				// I can do this a few different ways (I did this becuase I found a bug in one of the meathods:

				// 1. make another pointer to the remote memory I just read
				//&undocumented_remote_peb = (P_moonsols_win7_PEB)(&(remote_peb));
				//pebResult = pebHasAppCompatFlags((P_moonsols_win7_PEB)&remote_peb);	// not working for some reason	

				// 2. copy the memory into a new custom struct
				//memcpy(&undocumented_remote_peb, &remote_peb, bytes_read);	// PEB and undocumented PEB are different sizes so can't do this

				// 3. Re-read the remote memory
				ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &undocumented_remote_peb, sizeof(moonsols_win7_PEB), &bytes_read_for_undocumented_remote_peb);



				if (debuggingRemotePEBproblem){
					printf("Address of AppCompatFlag Low %#p has value %#x\n", &undocumented_remote_peb.AppCompatFlags.LowPart, undocumented_remote_peb.AppCompatFlags.LowPart);
					printf("Address of AppCompatFlag High %#p has value %#x\n", &undocumented_remote_peb.AppCompatFlags.HighPart, undocumented_remote_peb.AppCompatFlags.HighPart);
					printf("Address of AppCompatFlagsUser Low %#p has value %#x\n", &undocumented_remote_peb.AppCompatFlagsUser.LowPart, undocumented_remote_peb.AppCompatFlagsUser.LowPart);
					printf("Address of AppCompatFlagsUser High %#p has value %#x\n", &undocumented_remote_peb.AppCompatFlagsUser.HighPart, undocumented_remote_peb.AppCompatFlagsUser.HighPart);
					printf("Address of ShimData Pointer %#p has value %#x\n", &undocumented_remote_peb.pShimData, undocumented_remote_peb.pShimData);
					printf("Address of AppCompatInfo Pointer %#p has value %#x\n", &undocumented_remote_peb.AppCompatInfo, undocumented_remote_peb.AppCompatInfo);

					P_moonsols_win7_PEB localPEB = (P_moonsols_win7_PEB)pbi.PebBaseAddress;
					printf("Address of AppCompatFlag Low %#p has value %#x\n", &localPEB->AppCompatFlags.LowPart, localPEB->AppCompatFlags.LowPart);
					printf("Address of AppCompatFlag High %#p has value %#x\n", &localPEB->AppCompatFlags.HighPart, localPEB->AppCompatFlags.HighPart);
					printf("Address of AppCompatFlagsUser Low %#p has value %#x\n", &localPEB->AppCompatFlagsUser.LowPart, localPEB->AppCompatFlagsUser.LowPart);
					printf("Address of AppCompatFlagsUser High %#p has value %#x\n", &localPEB->AppCompatFlagsUser.HighPart, localPEB->AppCompatFlagsUser.HighPart);
					printf("Address of ShimData Pointer %#p has value %#x\n", &localPEB->pShimData, localPEB->pShimData);
					printf("Address of AppCompatInfo Pointer %#p has value %#x\n", &localPEB->AppCompatInfo, localPEB->AppCompatInfo);

					//memcpy(&undocumented_remote_peb, &remote_peb, bytes_read);

					int cmpResult = memcmp(&pbi.PebBaseAddress, &undocumented_remote_peb, bytes_read);

					printf("Result from Comparing the local PEB (pbi.PebBaseAddress) to the remote PEB (undocumented_remote_peb): ");
					if (cmpResult == 0)
						printf("Match\n");
					else if (cmpResult > 0)
						printf("Local PEB as some data at position %d that is a higher value than the remote PEB.\n", cmpResult);
					else if (cmpResult < 0)
						printf("Remote PEB as some data at position %d that is a higher value than the local PEB.\n", cmpResult);
					else
						printf("Some Weird error: %d\n", cmpResult);

					ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &undocumented_remote_peb, sizeof(_PEB), &bytes_read);

					printf("Remote PEB Address: %#p\n", pbi.PebBaseAddress);
					printf("Address of copied over PEB in current address space: %#p\n", &remote_peb);

				}




				if (
					undocumented_remote_peb.AppCompatFlags.LowPart == 0 &&
					undocumented_remote_peb.AppCompatFlags.HighPart == 0 &&
					undocumented_remote_peb.AppCompatFlagsUser.LowPart == 0 &&
					undocumented_remote_peb.AppCompatFlagsUser.HighPart == 0 &&
					undocumented_remote_peb.pShimData == 0 &&
					undocumented_remote_peb.AppCompatInfo == 0){
					if (veryVerbose || debug)
						printf("\tAll flags False. No Shim Flags detected\n");

					pebResult = FALSE;
				}
				else{
					printf("*****************************************************\n\n");
					printf("\tShim detected! One or more flags set!\n");
					// collect and read off memory values
					printf("\tAppCompatFlag %#x\n", undocumented_remote_peb.AppCompatFlags);
					printf("\tAppCompatFlag Low %#x\n", undocumented_remote_peb.AppCompatFlags.LowPart);
					printf("\tAppCompatFlag High %#x\n", undocumented_remote_peb.AppCompatFlags.HighPart);
					printf("\tAppCompatFlagsUser Low %#x\n", undocumented_remote_peb.AppCompatFlagsUser.LowPart);
					printf("\tAppCompatFlagsUser High %#x\n", undocumented_remote_peb.AppCompatFlagsUser.HighPart);
					printf("\tShimData Pointer %#p\n", undocumented_remote_peb.pShimData);
					printf("\tAppCompatInfo Pointer %#p\n", undocumented_remote_peb.AppCompatInfo);
					printf("*****************************************************\n\n");
					pebResult = TRUE;
				}

				// check the dll names

				// get address of Ldr from the PEB
				PPEB_LDR_DATA remote_ldr_pointer = remote_peb.Ldr;
				if (debug) printf("Remote Ldr Address: 0x%p\n", remote_ldr_pointer);

				// get the Ldr structure
				PEB_LDR_DATA remote_ldr = { 0 };
				status = ReadProcessMemory(pi.hProcess,
					remote_ldr_pointer,
					&remote_ldr,
					sizeof(PEB_LDR_DATA),
					&bytes_read);
				if (debug) printf("Address of copied over Ldr: 0x%p\n", &remote_ldr);

				// get the List entry struct from the Ldr
				LIST_ENTRY InMemoryOrderModuleList = (remote_ldr.InMemoryOrderModuleList);
				if (debug) printf("Address of copied over InMemoryOrderModuleList: 0x%p\n", &InMemoryOrderModuleList);

				// get the first link - Might be PLIST_ENTRY64
				LIST_ENTRY *address_of_remote_link = InMemoryOrderModuleList.Flink;
				if (debug) printf("Remote List Entry Address: 0x%p\n", address_of_remote_link);

				// calculate the address of the LDR_DATA_TABLE_ENTRY (of which the InMemoryOrderLinks is a member)
				LDR_DATA_TABLE_ENTRY *address_of_remote_ldr_ent = CONTAINING_RECORD(address_of_remote_link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				if (debug) printf("Remote LDR_DATA_TABLE_ENTRY Address: 0x%p\n", address_of_remote_ldr_ent);

				//get the actual remote Table Entry
				LDR_DATA_TABLE_ENTRY remote_ldr_ent = { 0 };
				status = ReadProcessMemory(pi.hProcess,
					address_of_remote_ldr_ent,
					&remote_ldr_ent,
					sizeof(LDR_DATA_TABLE_ENTRY),
					&bytes_read);
				if (debug) printf("Address of copied over LDR_DATA_TABLE_ENTRY Address: 0x%p\n", &remote_ldr_ent);

				if (debug) printf("Printing DLL list. Starting with: 0x%p\n", &remote_ldr_ent);
				unsigned int i = 0;
				while (TRUE){
					// the last entry will have a NULL for the name and for the address. Then it cycles back
					if (remote_ldr_ent.DllBase == NULL) break;

					// make the memory for the unicode string
					if (veryVerbose) printf("Making a Unicode String length of: %d. Max: %d\n", remote_ldr_ent.FullDllName.Length, remote_ldr_ent.FullDllName.MaximumLength);
					PWSTR namebuffer = (PWSTR)malloc(remote_ldr_ent.FullDllName.MaximumLength); // I don't know why the string lengths are sometimes smaller than what they say

					// get the string's buffer
					status = ReadProcessMemory(pi.hProcess,
						remote_ldr_ent.FullDllName.Buffer,
						namebuffer,
						remote_ldr_ent.FullDllName.MaximumLength,
						&bytes_read);

					// reconstruct unicode struct
					remote_ldr_ent.FullDllName.Buffer = namebuffer;

					// Check the DLL name
					if (veryVerbose) printf("\tx64 DLL Name: %wZ\n", remote_ldr_ent.FullDllName);

					//DllResultTemp = checkForKnownACdlls(remote_ldr_ent.FullDllName);	// enable this later
					DllResultTemp = FALSE;

					if (DllResultTemp && verbose){
						printf("Known Shimming DLL '%wZ' in %s\n", remote_ldr_ent.FullDllName, pe32.szExeFile);
					}
					DllResult = DllResult | DllResultTemp;

					LIST_ENTRY *address_of_next_remote_link = remote_ldr_ent.InMemoryOrderLinks.Flink;
					LDR_DATA_TABLE_ENTRY *address_of_next_remote_ldr_ent = CONTAINING_RECORD(address_of_next_remote_link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

					// free malloc'd string Because the code below will read in another table entry which will over write the pointer anyway
					free(remote_ldr_ent.FullDllName.Buffer);

					//get the actual remote Table Entry
					status = ReadProcessMemory(pi.hProcess,
						address_of_next_remote_ldr_ent,
						&remote_ldr_ent,
						sizeof(LDR_DATA_TABLE_ENTRY),
						&bytes_read);


				}// end while TRUE for looping over the remote LDR_DATA_TABLE_ENTRY entries

			}
			else {
				printf("Could not read other processes memory. Error: %d\n", GetLastError());
			}
		}
		else {
			printf("Could not get other process's PEB base address. Error: %d\n", GetLastError());
		}


		/////////////// Using the Documented way: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686849%28v=vs.85%29.aspx 
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;

		//  Take a snapshot of all modules in the specified process. 
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			printf("Failed at: CreateToolhelp32Snapshot (of modules)");
			return 0;
		}

		//  Set the size of the structure before using it. 
		me32.dwSize = sizeof(MODULEENTRY32);

		//  Retrieve information about the first module, 
		//  and exit if unsuccessful 
		if (!Module32First(hModuleSnap, &me32))
		{
			printf("Failed at Module32First");  // Show cause of failure 
			CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
			return 0;
		}

		//  Now walk the module list of the process, 
		//  and display information about each module 
		do
		{
			//printf("\n\n     MODULE NAME:     %s", me32.szModule);
			if (verbose){
				//printf("\tExecutable = %s\n", me32.szExePath);
			}


			exePath = getFileName(me32.szExePath);
			PUNICODE_STRING filename = unicodeStringFromCharArray(exePath);
			//printf("\t\tComparing Executable: '%wZ'\n", filename);
			DllResult = DllResult | checkForKnownACdlls(filename);
			//printf("\n     process ID     = 0x%08X", me32.th32ProcessID);
			//printf("\n     ref count (g)  =     0x%04X", me32.GlblcntUsage);
			//printf("\n     ref count (p)  =     0x%04X", me32.ProccntUsage);
			//printf("\n     base address   = 0x%08X", (DWORD)me32.modBaseAddr);
			//printf("\n     base size      = %d", me32.modBaseSize);

		} while (Module32Next(hModuleSnap, &me32));

		//  Do not forget to clean up the snapshot object. 
		CloseHandle(hModuleSnap);





		if (DllResult)
			printf("\tShimming DLL detected! One or more DLLs were found in process: %s\n", pe32.szExeFile);
		if (pebResult)
			printf("\tShim detected! One or more flags set in process: %s\n", pe32.szExeFile);
		//these are reset above, but just in case I'll do it here as well
		DllResult = FALSE;
		pebResult = FALSE;

	} // end NtQueryInformationProcess check
	else {

		if (result == STATUS_ACCESS_DENIED && (verbose || debug)){
			printf("STATUS_ACCESS_DENIED\n");
		}
		else if (result == STATUS_INVALID_HANDLE && (verbose || debug)){	// && !cmp ('system') && !cmp(' that other process name')
			printf("STATUS_INVALID_HANDLE\n");
		}
		else if (verbose || debug){
			printf("NtQuery Failed. Read out %d bytes. Error: 0x%p\n", pbi_len, result);
		}
	}


	return 0;
}

int main(void){

	// address of PEB meathod 1
	/*
	__asm
	{
	mov	eax, fs :0x30
	mov assmPEB, eax
	}

	__asm
	{
	mov	eax, gs :0x60
	mov assmPEB, eax
	}

	printf("Address of PEB: %x\n", assmPEB);
	*/


	// scan another process
	//WOW64_CONTEXT a;
	//Wow64GetThreadContext(threadHandle, &a);
	//a.SegGs;		// how does the gs:[0x60] work?


	// get peb


	// address of PEB meathod 2
	//PPEB peb = (PPEB)__readgsqword(0x30);

	// To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege 
	SetDebugPrivilege();

	// check my own PEB
	PPEB peb = (PPEB)__readgsqword(0x60);										// documented
	P_moonsols_win7_PEB local_peb_undocumented = (P_moonsols_win7_PEB)peb;			// undocumented 
	if (debuggingRemotePEBproblem){
		printf("Address of local x64 PEB: %#p\n", peb);
		printf("Address of local x32 PEB: %#p\n", __readgsdword(0x30));
	}

	printf("Checking for shim in local process...\n");
	if (pebHasAppCompatFlags(local_peb_undocumented)){
		printf("Shim Flags Detected in Self Process\n");
	}

	//pebHasAppCompatFlags
	/* mostly Working
	if (pebHasAppCompatDlls(peb_documented)){
	printf("Shim Detected in Self Process\n");
	}*/

	/* Not Working
	if (pebHasAppCompatFlags(peb)){
	printf("Shim Detected. Engaging Anti-Shim.\n");

	char thisFileName[MAX_PATH];
	char newFileName[MAX_PATH] = "XXXXXXXXXX.exe";

	// make new random file name
	int i;
	unsigned int    number;
	for (i = 0; i < 10; i++){
	rand_s(&number);
	number = number % 26;
	number += 0x41;
	newFileName[i] = number;
	}



	//At some point check against DeRandomizeExeName Fix


	// copy file
	GetModuleFileName(NULL, thisFileName, MAX_PATH);
	CopyFile(thisFileName, newFileName, FALSE);

	// pass on parameters except for the shim engine flag
	// execute file
	// look into preventing it from getting shimmed with environment variable
	//CreateProcess(newFileName, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, )

	// Look into:
	// PropagateProcessHistory
	// The problem occurs when an application incorrectly fails to apply an application fix.
	// The fix sets the _PROCESS_HISTORY environment variable so that child processes can look in the parent directory for matching information while searching for application fixes




	}*/


	printf("Checking Remote Processes...\n");


	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;


	//_moonsols_win7_PEB_LDR_DATA Ldr	// undocumented way
	_PEB_LDR_DATA Ldr;					// the documented way


	// start going through the first process
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot (of processes) Failed. Exiting.");
		return 0;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);


	// get context of the first thread of each process 
	/*
	WOW64_CONTEXT context;
	context.ContextFlags = (CONTEXT_FULL);
	BOOL contextSuccess = Wow64GetThreadContext(thread, &context);
	printf("eax=%08X, ebx=%08X, ecx=%08X\n", context.Eax, context.Ebx, context.Ecx);
	*/

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("Process32First Failed");	// show cause of failure
		CloseHandle(hProcessSnap);          // cleanup the snapshot object
		return 0;
	}


	BOOL pebResult = FALSE;
	BOOL DllResult = FALSE;

	PROCESS_INFORMATION pi = { 0 };

	do
	{

		if (debuggingRemotePEBproblem){
			printf("Remotely Scanning self Process\n");
			pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		}
		else {
			pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);	//PROCESS_ALL_ACCESS will normally work. With  READ_CONTROL I get a lot of access denied
		}

		if (verbose && !debuggingRemotePEBproblem){
			printf("Scanning Process \t%s", pe32.szExeFile);
			printf("\tPID \t%d\n", pe32.th32ProcessID);
		}

		// get the first remote thread, get the 32bit PEB from the FS register to get the 32 bit DLLs (ish)
		//WOW64_CONTEXT	Ctx_Wow64;
		//CONTEXT			Ctx_64;

		//ZeroMemory(&Ctx_64, sizeof(Ctx_64));
		//ZeroMemory(&Ctx_Wow64, sizeof(Ctx_Wow64));

		//Ctx_64.ContextFlags = CONTEXT_ALL;
		//Ctx_Wow64.ContextFlags = CONTEXT_ALL;

		//pi.hThread = 
		//BOOL ret = GetThreadContext(pi.hThread, &Ctx_64);





		if (pi.hProcess == 0){
			unsigned int lastError = GetLastError();
			if (lastError == 0x5){
				if (0 != strcmp(pe32.szExeFile, "System") && 0 != strcmp(pe32.szExeFile, "audiodg.exe")){ //"System" "Process" +	"audiodg.exe" cannot be read from
					printf("STATUS_ACCESS_DENIED for '%s' Try running with higher Privilages\n", pe32.szExeFile);
				}
			}
			else if (verbose || debug){
				printf("Could not get handle to process. Error: %d\n", lastError);
			}
		}

		// where all the actual work is done
		WORD remote32bitPEBAddress = 0;
		readRemoteProcessForShims(pe32, pi, remote32bitPEBAddress);

	} while (Process32Next(hProcessSnap, &pe32)); //end do while
	CloseHandle(hProcessSnap);





	/*
	// Access a shimmed registry value - The virt registry fix doesn't seem to work.
	DWORD BufferSize = 8192;
	PPERF_DATA_BLOCK PerfData = (PPERF_DATA_BLOCK)malloc(BufferSize);
	char buffer[8192];
	LONG returnStatus = RegGetValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SamsungRapidApp", RRF_RT_ANY, NULL, (PVOID)&buffer, &BufferSize);
	if (returnStatus == ERROR_SUCCESS){
	printf("\n\nRead %d bytes correctly (no shim)\n", BufferSize);
	printf("%s\n", buffer);
	}
	else {
	printf("\nShim Worked - RegQueryValueEx failed (%d)\n", returnStatus);
	}
	*/



	return 0;
}


/*
sdb file names
// known XP x86
apph_sp.sdb
apphelp.sdb
drvmain.sdb
msimain.sdb
sysmain.sdb


//mal
VC_browsers32.sdb
VC_browsers64,sdb



*/