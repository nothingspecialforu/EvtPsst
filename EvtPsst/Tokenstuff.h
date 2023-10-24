#pragma once
#include <Windows.h>
#include <sddl.h>


HANDLE ImpersonateTokenofPID(DWORD dwPID);
DWORD checkTokenGroups(HANDLE hToken);
PTOKEN_GROUPS getTokenInfos(HANDLE hToken, PDWORD dwLengthneeded);