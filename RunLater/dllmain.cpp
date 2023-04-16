// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <Windows.h>
#include <detours.h>
#include <string>
#include <cstdlib>
#include <fstream>
#include <locale>
#include <codecvt>

static auto OriginalCreateProcess = &CreateProcessW;
const char* ExternDllPath = "C:\\\\_DLL.dll";

bool FileExists(const std::string& path) {
	std::ifstream infile(path.c_str());
	return infile.good();
}

char* LPCWSTRToCString(LPCWSTR wstr) {
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* cstr = (char*)malloc(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, cstr, size_needed, NULL, NULL);
	return cstr;
}

char* LPWSTRToCString(LPWSTR wstr) {
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* cstr = (char*)malloc(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, cstr, size_needed, NULL, NULL);
	return cstr;
}

std::string FormatString(const char* lpcszFormat, ...)
{
	char* pszStr = NULL;
	if (NULL != lpcszFormat)
	{
		va_list marker = NULL;
		va_start(marker, lpcszFormat);

		size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
		pszStr = new char[nLength];
		memset(pszStr, '\0', nLength);
		_vsnprintf_s(pszStr, nLength, nLength, lpcszFormat, marker);

		va_end(marker);
	}
	std::string strResult(pszStr);
	delete[]pszStr;
	return strResult;
}

std::wstring StringToWString(const std::string& str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(str);
}

BOOL WINAPI HookedCreateProcess(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	std::string str;

	char* ApplicationName = LPCWSTRToCString(lpApplicationName);
	char* CommandLine = LPWSTRToCString(lpCommandLine);

	str = FormatString(
		"Path to dll will be injected: \"%s\"\n"
		"CreateProcess hooked, Parent Process Paused.\n"
		"ApplicationName=%s\n"
		"CommandLine=%s\n"
		"Press OK to Continue & Resume.",
		ExternDllPath,
		ApplicationName,
		CommandLine);
	MessageBox(0, str.c_str(), "RunLater", MB_OK);

	std::string szCommandLine = std::string(CommandLine);
	if (FileExists(ExternDllPath))
	{
		std::string szDllPath = ExternDllPath;
		std::string szCommandLine = "\"" + std::string(CommandLine) + "\" \"" + szDllPath + "\"";
	}

	auto result = OriginalCreateProcess(
		lpApplicationName,
		const_cast<LPWSTR>(StringToWString(szCommandLine).c_str()),
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | LOAD_LIBRARY_SEARCH_SYSTEM32,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);

	str = FormatString("CreateProcess Call Finished, Parent Process Paused.\n"
		"CreateProcess returns %d\n"
		"Press OK to Continue & Resume.", result);
	MessageBox(0, str.c_str(), "RunLater", MB_OK);


	delete ApplicationName, CommandLine;

	return result;
}

extern "C" __declspec(dllexport)
BOOL HookCreateProcess()
{
	if (DetourTransactionBegin() != NO_ERROR) {
		return FALSE;
	}

	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	if (DetourAttach(&(LPVOID&)OriginalCreateProcess, HookedCreateProcess) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	if (DetourTransactionCommit() != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	return TRUE;
}

extern "C" __declspec(dllexport)
BOOL UnhookCreateProcess()
{
	if (DetourTransactionBegin() != NO_ERROR) {
		return FALSE;
	}

	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	if (DetourDetach(&(LPVOID&)OriginalCreateProcess, HookedCreateProcess) != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	if (DetourTransactionCommit() != NO_ERROR) {
		DetourTransactionAbort();
		return FALSE;
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		MessageBox(0, "(Signal DLL_PROCESS_ATTACH) Injected", "RunLater.dll", 0);
		DisableThreadLibraryCalls(hModule);
		HookCreateProcess();
		break;

	case DLL_PROCESS_DETACH():
		UnhookCreateProcess();
		MessageBox(0, "(Signal PROCESS_DETACH) Unhooked.", "RunLater.dll", 0);
		break;
	}

	return TRUE;
}
