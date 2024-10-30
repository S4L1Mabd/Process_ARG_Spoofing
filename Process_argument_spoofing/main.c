#include"func.h"

BOOL verifier = FALSE;
LPCWSTR applicationName = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
LPWSTR fakeargs = L"am fake lol";
LPWSTR realargs = L"-c calc.exe";
DWORD ProcessID = NULL;
HANDLE hProcess, hThread = NULL;

int main() {

	printf("hello \n");

	char GGG = getchar();

	verifier = CreateSpoofedProcess(applicationName, fakeargs, realargs, &ProcessID, &hProcess, &hThread);
	
	if (!verifier) {

		printf("[-] WLAH Marak Ma spofiihaa \n ");
		return 0;
	}

	printf("[+] We spoofed the process with PID : %lu ", ProcessID);

	char GG = getchar();
	return 0;


}