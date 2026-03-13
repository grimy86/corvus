#include "ProcessController.h"

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
		const ACCESS_MASK accessMask)
	{
		if (!Muninn::Data::IsValidProcessId(processId))
			return false;
		if (Muninn::Data::IsValidHandle(m_processHandle))
			return false;

		NTSTATUS status{ Muninn::Data::OpenProcessHandleNt(
			processId,
			accessMask,
			&m_processHandle) };

		if (!NT_SUCCESS(status))
			return false;

		if (!Muninn::Data::IsValidHandle(m_processHandle))
			return false;
		else return true;
	}

	bool ProcessController::DisposeHandle()
	{
		if (!Muninn::Data::IsValidHandle(m_processHandle))
			return true;

		if (!Muninn::Data::CloseHandleNt(m_processHandle))
			return false;

		m_processHandle = nullptr;
		return true;
	}

	bool ProcessController::InitializeProcessEntry32(const DWORD processId)
	{
		if (!Muninn::Data::IsValidProcessId(processId))
			return false;
		if (!Muninn::Data::IsValidHandle(m_processHandle))
			return false;

		m_process32.processEntry = {};


	}

	const Muninn::Object::ProcessObject&
		ProcessController::GetProcessObject32() const noexcept
	{
		return m_process32;
	}

	const Muninn::Object::ProcessObject&
		ProcessController::GetProcessObjectNt() const noexcept
	{
		return m_processNt;
	}

	const HANDLE&
		ProcessController::GetProcessHandle() const noexcept
	{
		return m_processHandle;
	}
}