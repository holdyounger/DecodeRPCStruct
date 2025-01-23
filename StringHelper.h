#pragma once

#include <iostream>
#include <Windows.h>

WCHAR* CharToWchar(CHAR* sSour)
{
	size_t len = strlen(sSour) + 1;
	size_t converted = 0;
	WCHAR* wzDest = NULL;
	wzDest = (WCHAR*)new WCHAR[len];
	mbstowcs_s(&converted, wzDest, len, sSour, _TRUNCATE);
	return wzDest;
}

char* WCharToChar(WCHAR* wzSour)
{
	ULONG ulLength = 0;
	char* szDest = NULL;

	if (wzSour != NULL)
	{
		ulLength = WideCharToMultiByte(CP_ACP, NULL, wzSour, -1, NULL, 0, NULL, FALSE);
		szDest = new char[ulLength + 1];
		if (szDest == NULL)
		{
			return NULL;
		}
		memset(szDest, 0, ulLength + 1);
		WideCharToMultiByte(CP_OEMCP, NULL, wzSour, -1, szDest, ulLength, NULL, FALSE);
	}
	return szDest;
}