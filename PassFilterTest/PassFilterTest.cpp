#include <iostream>
#include "PassFilter.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <climits>

bool unicodeStringInit(PUNICODE_STRING ucs, const wchar_t* source)
{
	size_t chars = wcslen(source);
	
	if ((chars + 1) > (USHRT_MAX / sizeof(wchar_t)))
	{
		// to big for an UNICODE_STRING 
		return false;
	}

	// disable conversion warning. we check for overflow above
	#pragma warning( disable : 4267 )
	// Length in bytes
	ucs->Length = chars * sizeof(wchar_t);
	// Length of buffer including terminator in bytes
	ucs->MaximumLength = (chars + 1) * sizeof(wchar_t);
	#pragma warning( default : 4267 )

	ucs->Buffer = new (std::nothrow) wchar_t[chars + 1];
	if (ucs->Buffer == nullptr)
	{
		return false;
	}
	wcscpy_s(ucs->Buffer, ucs->MaximumLength, source);

	return true;
}

int main()
{
	UNICODE_STRING username, fullname, password;

	if (!unicodeStringInit(&username, L"Test")) {
		std::cout << "Username init failed!\n";
		return 1;
	}

	if (!unicodeStringInit(&fullname, L"Test")) {
		std::cout << "Fullname init failed!\n";
		return 1;
	}

	//TODO: Change password here
	if (!unicodeStringInit(&password, L"masterpassword123!")) {
		std::cout << "Password init failed!\n";
		return 1;
	}

	if (PasswordFilter(&username, &fullname, &password, TRUE)) {
		std::cout << "Password cleared filter.\n";
	}
	else {
		std::cout << "Password FAILED filter!\n";
	}

	return 0;
}
