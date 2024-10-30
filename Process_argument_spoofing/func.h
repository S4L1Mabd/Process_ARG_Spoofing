#pragma once
#include<windows.h>
#include<stdio.h>
#include<winternl.h>

#define FUNC_H





/* BOOL ReadProcessMemory(
	IN HANDLE hProcess,
	IN LPCVOID lpBaseAddress,
	OUT LPVOID lpBuffer,
	IN SIZE_T nSize,
    OUT SIZE_T* lpNumberOfBytesRead
); */

/* BOOL WriteProcessMemory(
	IN HANDLE hProcess,
	IN LPVOID lpBaseAddress, // What is being overwritten(CommandLine.Buffer)
	IN LPCVOID lpBuffer, // What is being written (newprocess argument)
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
	); */

BOOL ReadfromTargetProcess(IN HANDLE hProcess , IN PVOID pAdress , OUT PVOID* Buffer , IN DWORD dwBufSize);
BOOL WriteToTargProcess(IN HANDLE hProcess, IN PVOID PaddressToWrite, IN PVOID pBuffer, IN DWORD dwBufSize);
BOOL CreateSpoofedProcess(IN LPWSTR AppName,IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);