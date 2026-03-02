#include "MemoryService.h"
#include "ProcessController.h"
#include "WindowsProviderNt.h"

namespace Corvus::Controller
{
	ProcessController::ProcessController(
		const DWORD processId,
		const ACCESS_MASK processAccessMask)
	{
		if (!InitializeHandle(processId, processAccessMask))
		{
			m_state = ControllerState::Uninitialized;
		}
	}

	ProcessController::~ProcessController()
	{
		Dispose();
	}

	bool ProcessController::InitializeHandle(
		const DWORD processId,
		const ACCESS_MASK processAccessMask)
	{
		if (m_state != ControllerState::Uninitialized)
		{
			m_state = ControllerState::Error;
			return false;
		}

		if (!Corvus::Data::IsValidProcessId(processId))
		{
			m_state = ControllerState::Error;
			return false;
		}

		m_processHandle
			= Corvus::Data::OpenProcessHandleNt(processId, processAccessMask);
		if (!Corvus::Data::IsValidHandle(m_processHandle))
		{
			m_state = ControllerState::Error;
			return false;
		}

		m_state = ControllerState::Initialized;
		return true;
	}

	bool ProcessController::InitializeProcessObject32(const DWORD processId)
	{
		return true;
	}

	bool ProcessController::Dispose()
	{
		if (m_state != ControllerState::Initialized)
		{
			m_state = ControllerState::Error;
			return false;
		}

		if (!Corvus::Data::IsValidHandle(m_processHandle))
		{
			m_state = ControllerState::Error;
			return false;
		}

		if (!Corvus::Data::CloseHandleNt(m_processHandle))
		{
			m_state = ControllerState::Error;
			return false;
		}

		m_state = ControllerState::Disposed;
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

	const ControllerState& ProcessController::GetState() const noexcept
	{
		return m_state;
	}
}