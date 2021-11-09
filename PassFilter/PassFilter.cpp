// PassFilter.cpp : Hiermit werden die exportierten Funktionen für die DLL definiert.
//

#include "pch.h"
#include "PassFilter.h"
#include "sha1.h"

/*
 * Simple array compare that is vulnerable to buffer overflows
 */
int compare_hash(unsigned char* a, unsigned char* b, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (a[i] < b[i]) return -1;
		if (a[i] > b[i]) return 1;
	}
	return 0;
}

/*
* Checks if we can read the config reg key and how long the data are, then reads it into a buffer or assigns a default.
*/
wchar_t* readRegPath() {
	wchar_t* regPath = nullptr;
	// holds the size of the read reg key after calling RegGetValue
	DWORD buffSize = 1024;

	// Check if key exists and is readable. If so, this sets buffSize to the amount of bytes needed to store the value.
	LSTATUS ret = RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Passfilter", L"HashFile", RRF_RT_ANY, NULL, NULL, &buffSize);

	// The reg provides will give ERROR_FILE_NOT_FOUND if either the key or the value doesn't exist.
	if (ret == ERROR_FILE_NOT_FOUND)
	{
		//TODO: Instead of having the default in-app, create the reg key if it doesn't exist.
		const wchar_t* tmp = L"C:\\Windows\\System32\\hibp\\hibp.bin";
		size_t len = wcslen(tmp) + 1;
		regPath = new (std::nothrow) wchar_t[len];
		if (regPath == nullptr)
		{
			return nullptr;
		}
		wcscpy_s(regPath, len, tmp);
	}
	else if (ret != ERROR_SUCCESS)
	{
		return nullptr;
	}
	else
	{
		regPath = new (std::nothrow) wchar_t[buffSize];
		if (regPath == nullptr)
		{
			return nullptr;
		}

		ret = RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Passfilter", L"HashFile", RRF_RT_ANY, NULL, (PVOID)regPath, &buffSize);
		if (ret != ERROR_SUCCESS || regPath[0] == 0)
		{
			delete[] regPath;
			return nullptr;
		}
	}
	return regPath;
}

/*
* Convert the UTF16 UNICODE_STRING to a UTF8 char* to be able to properly hash it.
*/
char* convertToUTF8(PUNICODE_STRING password, int& utf8Len) {
	utf8Len = WideCharToMultiByte(CP_UTF8, 0, password->Buffer, -1, nullptr, 0, nullptr, nullptr);

	char* pw = new (std::nothrow) char[utf8Len];
	if (pw == nullptr)
	{
		return nullptr;
	}

	int bytesWritten = WideCharToMultiByte(CP_UTF8, 0, password->Buffer, -1, pw, utf8Len, nullptr, nullptr);
	if (bytesWritten != utf8Len)
	{
		SecureZeroMemory(pw, utf8Len);
		delete[] pw;
		return nullptr;
	}

	return pw;
}

/*
* Uses the Windows API to get an accurate Filesize. May not work on x86.
*/
bool getFileSize(wchar_t* regPath, size_t& bytes) {
	HANDLE handle = CreateFile2((LPCWSTR)regPath, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	LARGE_INTEGER lFileSize;
	BOOL good = GetFileSizeEx(handle, &lFileSize);
	CloseHandle(handle);
	if (!good)
	{
		return false;
	}
	bytes = lFileSize.QuadPart;
	return true;
}

/*
* Standard binary search.
* Returns true on error or if the value is found.
* Returns false if value is not found.
*/
bool binSearch(std::ifstream& hibp, size_t bytes, unsigned char* pwHash) {
	size_t lower = 0;
	size_t upper = (bytes / 20) - 1;

	int cmp;
	char hashBuffer[20];

	// Binary search function
	while (lower <= upper)
	{
		size_t position = lower + (upper - lower) / 2L;

		hibp.seekg(position * 20L);
		hibp.read(hashBuffer, 20);

		if (hibp.gcount() != 20)
		{
			return true;
		}

		cmp = compare_hash(pwHash, (unsigned char*)hashBuffer, 20);
		// we got a match <3
		if (cmp == 0)
		{
			return true;
		}
		// pwHash is greater than current position
		else if (cmp > 0)
		{
			lower = position + 1;
		}
		// pwHash is smaller than current position
		else if (cmp < 0)
		{
			upper = position - 1;
		}
	}
	return false;
}

/*
* The value returned by this function determines whether the new password is accepted by the system.
* 
* TRUE
*	Returns TRUE if the new password is valid with respect to the password policy.
*	When TRUE is returned, the Local Security Authority (LSA) continues to evaluate the password by calling any other password filters installed on the system.
*
* FALSE
*	Returns FALSE if the new password is not valid with respect to the password policy.
*	When FALSE is returned, the LSA returns the ERROR_ILL_FORMED_PASSWORD (1324) status code to the source of the password change request. 
* 
* All buffers passed into password notification and filter routines should be treated as read-only. Writing data to these buffers may cause unstable behavior.
*/
extern "C" PASSFILTER_API BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation)
{
	wchar_t* regPath = readRegPath();
	if (regPath == nullptr)
	{
		return FALSE;
	}

	int utf8Len = 0;
	char* pw = convertToUTF8(Password, utf8Len);
	if (pw == nullptr) {
		delete[] regPath;
		return FALSE;
	}

	unsigned char pwHash[21] = { 0 };

	// the utf8 string is null terminated, so we exclude this here.
	bool res = NT_SUCCESS(sha1(pw, utf8Len - 1, (char*)pwHash));
	SecureZeroMemory(pw, utf8Len);
	delete[] pw;

	if (!res)
	{
		SecureZeroMemory(pwHash, 20);
		delete[] regPath;
		return FALSE;
	}

	size_t bytes = 0;
	if (!getFileSize(regPath, bytes)) {
		SecureZeroMemory(pwHash, 20);
		delete[] regPath;
		return FALSE;
	}

	// A properly converted hibp file will be a multiple of 20 bytes (length of a SHA1 hash)
	if (bytes % 20 != 0)
	{
		SecureZeroMemory(pwHash, 20);
		delete[] regPath;
		return FALSE;
	}

	std::ifstream hibp(regPath, std::ios::binary);
	delete[] regPath;

	// Steams don't throw, so we need to check this.
	if (hibp.fail()) {
		SecureZeroMemory(pwHash, 20);
		return FALSE;
	}

	bool foundOrError = binSearch(hibp, bytes, pwHash);

	hibp.close();
	SecureZeroMemory(pwHash, 20);

	if (foundOrError)
	{
		return FALSE;
	}

	// Password passed the filter
	return TRUE;
}