#include "Log.h"
#include "SystemInfo.h"
#include "Injector.h"
#include <ProcessController.h>

const wchar_t* processName{ L"ac_client.exe" };
const wchar_t* dllPath{ L"C:\\Users\\Amend\\source\\repos\\grimy86\\Muninn\\Debug\\Dll.dll" };
bool isRunning{ false };
bool success{ false };
DWORD processId{ 0ul };

int main()
{
	processId = Muninn::Controller::ProcessController::FindProcessId(
		processName,
		isRunning);

	if (!isRunning)
	{
		Log(ConsoleColor::Red, "Please run the process first.");
		return 1;
	}

	Muninn::Controller::ProcessController* pProcessController{
	new Muninn::Controller::ProcessController(
		processId,
		PROCESS_ALL_ACCESS) };
		
	uintptr_t processHandle{
		reinterpret_cast<uintptr_t>(
			pProcessController->GetProcess().processHandle) };

	success = pProcessController->RefreshProcessEntry();
	
	if (!success)
	{
		Log(ConsoleColor::Red, "Failed to initialize process entry.");
		delete pProcessController;
		pProcessController = nullptr;
		return 1;
	}

	success = pProcessController->RefreshModuleList();

	if (!success)
	{
		Log(ConsoleColor::Red, "Failed to initialize module list.");
		delete pProcessController;
		pProcessController = nullptr;
		return 1;
	}

	/* TESTED, WORKING
	ShowProcessEntry(pProcessController);
	NewLine();
	ShowProcessModules(pProcessController);
	NewLine();
	*/

	pProcessController->SetInjectorDllPathW(dllPath);
	SimpleInjectDll(pProcessController);
	NewLine();

	delete pProcessController;
	pProcessController = nullptr;
	return 0;
};