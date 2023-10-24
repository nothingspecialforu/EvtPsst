#include <Windows.h>
#include <stdio.h>
#include "EvtPsst.h"
#include "Tokenstuff.h"


HANDLE ImpersonateTokenofPID(DWORD dwPID) {
	
	DWORD dwSuccess = FAIL;
	BOOL bSuccess = FALSE;
	
	HANDLE hProcess = NULL;

	HANDLE hToken = NULL;
	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == NULL) {
		goto exit;
	}

	dwSuccess = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE, &hToken);
	if (dwSuccess == FAIL) {
		printf("[-] Could not open process token of PID: %d\n", dwPID);
		goto exit;
	}
	bSuccess = ImpersonateLoggedOnUser(hToken);
	if (bSuccess == FAIL) {
		printf("[-] Could not impersonate Token of the PID: %d\n", dwPID);
		goto exit;
	}

exit:

	return hToken;
}


PTOKEN_GROUPS getTokenInfos(HANDLE hToken, PDWORD dwLengthneeded) {
	DWORD dwLength = 0;
	DWORD dwSuccess = 0;
	PTOKEN_GROUPS pTokenGroupPrivileges = NULL;
	dwSuccess = GetTokenInformation(hToken, TokenGroups, NULL, dwLength, &dwLength);


	pTokenGroupPrivileges = (PTOKEN_GROUPS)VirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);
	if (pTokenGroupPrivileges == NULL) {
		printf("[-] Could not allocate space");
		goto exit;
	}

	dwSuccess = GetTokenInformation(hToken, TokenGroups, pTokenGroupPrivileges, dwLength, &dwLength);
	if (dwSuccess == 0) {
		printf("[-] Could not get Token information in func\n");
		goto exit;
	}
	*dwLengthneeded = dwLength;
	return pTokenGroupPrivileges;

exit:
	return NULL;
}

DWORD checkTokenGroups(HANDLE hToken) {
	DWORD dwSuccess = FAIL;
	DWORD dwSizeneeded = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;
	pTokenGroups = getTokenInfos(hToken, &dwSizeneeded);

	if (pTokenGroups == NULL) {
		printf("[-] No Token Groups found\n");
		return dwSuccess;
	}


	PSID_AND_ATTRIBUTES pSidAttributes, pSidAttributesorig = NULL;
	pSidAttributesorig = pTokenGroups->Groups;
	DWORD dwCountGroups = 0;
	dwCountGroups = pTokenGroups->GroupCount;

	

	for (DWORD i = 0; i < dwCountGroups; i++) {
		pSidAttributes = (PSID_AND_ATTRIBUTES)((PBYTE)pSidAttributesorig + (BYTE)(i * (BYTE)sizeof(SID_AND_ATTRIBUTES)));

		PSID pSID = NULL;
		pSID = (PSID)(pSidAttributes->Sid);

		LPTSTR psidString = NULL;
		WCHAR username[MAX_NAME] = { 0x00 };
		WCHAR domainname[MAX_NAME] = { 0x00 };
		SID_NAME_USE sidtype = { 0x00 };
		DWORD dwSizeUserName = sizeof(username);
		DWORD dwSizeDomainName = sizeof(domainname);


		dwSuccess = ConvertSidToStringSidW(pSID, &psidString);
		if (dwSuccess == FAIL) {
			continue;
		}
		if (psidString == NULL) {
			printf("[-] Got no SID\n");
			continue;
		}

		

		dwSuccess = LookupAccountSid(NULL, pSID, username, &dwSizeUserName, domainname, &dwSizeDomainName, &sidtype);
		if (dwSuccess == FAIL) {
			if (ERROR_NONE_MAPPED != GetLastError()) {
				//Mapping is some times not possible
				printf("[-] Could not Lookup SID\n");
			}		
			continue;
		}
		dwSuccess = FAIL;
		if (lstrcmpW(username, L"EventLog") == 0) {
			dwSuccess = SUCCESS;
			goto exit;
		}

	}

exit:
	if (pTokenGroups) {
		VirtualFree(pTokenGroups, 0, MEM_RELEASE);
	}
	
	return dwSuccess;


}