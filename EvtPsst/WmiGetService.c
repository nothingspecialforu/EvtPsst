#include <Windows.h>
#include <WbemIdl.h>
#include <ShObjIdl.h>
#include <stdint.h>
#include <stdio.h>
#include "EvtPsst.h"


DWORD getPidsfromService(PDWORD dwPidEventlog, PDWORD dwPidRPCSs, PDWORD dwPidUserProfService) {

	DWORD dwSuccess = FAIL;



	wchar_t w_nameserviceevt[] = L"EventLog";
	wchar_t w_nameservicerpcss[] = L"RpcSs";
	wchar_t w_nameserviceuserprof[] = L"ProfSvc";
	


	GUID _CLSID_WbemLocator = { 0x4590f811, 0x1d3a, 0x11d0 , { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
	IID   _IID_IWbemLocator = { 0xdc12a687, 0x737f, 0x11cf , { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

	wchar_t w_server[] = L"ROOT\\CIMV2";
	wchar_t w_wql[] = L"WQL";
	wchar_t w_query[] = L"select name, processid from Win32_Service";


	wchar_t w_column_name[] = L"name";
	wchar_t w_column_processid[] = L"processid";

	BSTR bstr_server = NULL;
	BSTR bstr_wql = NULL;
	BSTR bstr_query = NULL;

	HRESULT h_res = 0;
	IWbemLocator* p_loc = NULL;
	IWbemServices* p_svc = NULL;
	IEnumWbemClassObject* p_enumerator = NULL;
	IWbemClassObject* p_cls_obj = NULL;
	VARIANT vt_prop = { 0x00 };
	ULONG u_return = 0x00;
	
	uint32_t pid_eventservice = 0x00;


	bstr_server = SysAllocString(w_server);
	bstr_wql = SysAllocString(w_wql);
	bstr_query = SysAllocString(w_query);

	if (bstr_server == NULL || bstr_wql == NULL || bstr_query == NULL) {
		printf("Could not convert to bstr\n");
		goto exit;
	}

	h_res = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(h_res)) {
		printf("[-] Could not initialize Context\n");
		goto exit;
	}

	h_res = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(h_res)) {
		printf("[-] Could not inizialize Security Settings\n");
		goto exit;
	}

	h_res = CoCreateInstance(&_CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &_IID_IWbemLocator, (LPVOID*)&p_loc);
	if (FAILED(h_res)) {
		printf("[-] Could not create Instance\n");
		goto exit;
	}

	if (p_loc == NULL) {
		printf("[-] WbemLocator Null Pointer\n");
		goto exit;
	}

	h_res = p_loc->lpVtbl->ConnectServer(p_loc, bstr_server, NULL, NULL, 0, 0, 0, 0, &p_svc);
	if (FAILED(h_res)) {
		printf("[-] Could not connect to the server\n");
		goto exit;
	}

	h_res = p_svc->lpVtbl->ExecQuery(p_svc, bstr_wql, bstr_query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &p_enumerator);
	if (FAILED(h_res)) {
		printf("[-] Query Execution failed\n");
		goto exit;
	}


	while (p_enumerator) {

		h_res = p_enumerator->lpVtbl->Next(p_enumerator, WBEM_INFINITE, 1, &p_cls_obj, &u_return);
		if (FAILED(h_res))
			goto exit;

		if (u_return == 0x00)
			break;

		h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_name, 0, &vt_prop, 0, 0);
		if (FAILED(h_res))
			goto exit;

		if (!lstrcmpW(vt_prop.bstrVal, w_nameserviceevt)) {

			h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_processid, 0, &vt_prop, 0, 0);
			if (FAILED(h_res)) {
				printf("[-] Get Value EventLog failed\n");
				goto exit;
			}

			*dwPidEventlog = vt_prop.lVal;
			continue;

		}

		if (!lstrcmpW(vt_prop.bstrVal, w_nameservicerpcss)) {

			h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_processid, 0, &vt_prop, 0, 0);
			if (FAILED(h_res)) {
				printf("[-] Get Value RpcSs failed\n");
				goto exit;
			}

			*dwPidRPCSs = vt_prop.lVal;
			continue;

		}

		if (!lstrcmpW(vt_prop.bstrVal, w_nameserviceuserprof)) {

			h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_processid, 0, &vt_prop, 0, 0);
			if (FAILED(h_res)) {
				printf("[-] Get Value ProfSvc failed\n");
				goto exit;
			}

			*dwPidUserProfService = vt_prop.lVal;
			continue;

		}

	}
	dwSuccess = SUCCESS;

exit:
	return dwSuccess;

}
