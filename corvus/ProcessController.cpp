#include "ProcessController.h"
#include "MemoryService.h"
#include "WindowsProviderNt.h"

namespace Corvus::Controller
{
	ProcessController::ProcessController(
		const DWORD processId,
		const ACCESS_MASK processAccessMask)
	{
		if (!InitializeHandle(processId, processAccessMask))
			return;
	}

	ProcessController::~ProcessController()
	{
		if (!DisposeHandle());
	}

	bool ProcessController::InitializeHandle(
		const DWORD processId,
		const ACCESS_MASK processAccessMask)
	{
		// Already has a handle
		if (Corvus::Data::IsValidHandle(m_processHandle)) return false;

		// Doesn't have a handle yet but the processId is invalid
		if (!Corvus::Data::IsValidProcessId(processId)) return false;

		// The processId is valid, opening a handle
		m_processHandle
			= Corvus::Data::OpenProcessHandleNt(processId, processAccessMask);

		// Handle validation check
		if (!Corvus::Data::IsValidHandle(m_processHandle)) return false;
		else return true;
	}

	bool ProcessController::DisposeHandle()
	{
		// Already disposed or invalid
		if (!Corvus::Data::IsValidHandle(m_processHandle))
			return true;

		// Failed to close
		if (!Corvus::Data::CloseHandleNt(m_processHandle))
			return false;

		m_processHandle = nullptr;
		return true;
	}

	/*
	bool ProcessController::InitializeProcessObject32(const DWORD processId)
	{
		// We don't have a valid handle yet
		if (!Corvus::Data::IsValidHandle(m_processHandle))
			return false;

		Corvus::Object::ProcessEntry processEntry{};
		if (!Corvus::Data::GetProcessInformationObject32(processId, processEntry))
			return false;
	}
	*/

	bool ProcessController::InitializeProcessObjectNt(const DWORD processId)
	{

		return true;
	}

	const Corvus::Object::ProcessObject& ProcessController::GetProcessObject32() const noexcept
	{
		return m_process32;
	}

	const Corvus::Object::ProcessObject& ProcessController::GetProcessObjectNt() const noexcept
	{
		return m_processNt;
	}

	const HANDLE& ProcessController::GetProcessHandle() const noexcept
	{
		return m_processHandle;
	}
}