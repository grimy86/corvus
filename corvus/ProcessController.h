#pragma once
#include "WindowsStructures.h"
#include "ControllerState.h"
#include <Windows.h>
#include <vector>

namespace Corvus::Controller
{
	class ProcessController final
	{
	private:
		Corvus::Object::ProcessObject m_process32{};
		Corvus::Object::ProcessObject m_processNt{};
		HANDLE m_processHandle{};
		ControllerState m_state{ ControllerState::Uninitialized };

		bool InitializeHandle(
			const DWORD processId,
			const ACCESS_MASK processAccessMask);

		bool Dispose();
		bool InitializeProcessObject32(const DWORD processId);

	public:
		ProcessController() = default;
		ProcessController(const DWORD processId, const ACCESS_MASK processAccessMask);
		~ProcessController() = default;

		// Delete copy constructor and copy assignment operator
		ProcessController(const ProcessController&) = delete;
		ProcessController& operator=(const ProcessController&) = delete;

		const Corvus::Object::ProcessObject& GetProcessObject32() const noexcept;
		const Corvus::Object::ProcessObject& GetProcessObjectNt() const noexcept;
		const HANDLE& GetProcessHandle() const noexcept;
		const ControllerState& GetState() const noexcept;
	};
}