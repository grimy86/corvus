#include "ProcessController.h"
#include "MemoryService.h"
#include "WindowsProviderNt.h"

namespace Muninn::Controller
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
		if (Muninn::Data::IsValidHandle(m_processHandle)) return false;

		// Doesn't have a handle yet but the processId is invalid
		if (!Muninn::Data::IsValidProcessId(processId)) return false;

		// The processId is valid, opening a handle
		m_processHandle
			= Muninn::Data::OpenProcessHandleNt(processId, processAccessMask);

		// Handle validation check
		if (!Muninn::Data::IsValidHandle(m_processHandle)) return false;
		else return true;
	}

	bool ProcessController::DisposeHandle()
	{
		// Already disposed or invalid
		if (!Muninn::Data::IsValidHandle(m_processHandle))
			return true;

		// Failed to close
		if (!Muninn::Data::CloseHandleNt(m_processHandle))
			return false;

		m_processHandle = nullptr;
		return true;
	}

	/*
	bool ProcessController::InitializeProcessObject32(const DWORD processId)
	{
		// We don't have a valid handle yet
		if (!Muninn::Data::IsValidHandle(m_processHandle))
			return false;

		Muninn::Object::ProcessEntry processEntry{};
		if (!Muninn::Data::GetProcessInformationObject32(processId, processEntry))
			return false;
	}
	*/

	bool ProcessController::InitializeProcessObjectNt(const DWORD processId)
	{

		return true;
	}

	const Muninn::Object::ProcessObject& ProcessController::GetProcessObject32() const noexcept
	{
		return m_process32;
	}

	const Muninn::Object::ProcessObject& ProcessController::GetProcessObjectNt() const noexcept
	{
		return m_processNt;
	}

	const HANDLE& ProcessController::GetProcessHandle() const noexcept
	{
		return m_processHandle;
	}
}