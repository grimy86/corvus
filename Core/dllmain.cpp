#include <phnt_windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Code to run when the DLL is loaded into a process
		break;
	case DLL_THREAD_ATTACH:
		// Code to run when a new thread is created in the process
		break;
	case DLL_THREAD_DETACH:
		// Code to run when a thread exits cleanly
		break;
	case DLL_PROCESS_DETACH:
		// Code to run when the DLL is unloaded from a process
		break;
	}
	return TRUE; // indicate successful load
}