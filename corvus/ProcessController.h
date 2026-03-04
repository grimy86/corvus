#pragma once
#include "WindowsStructures.h"

namespace Corvus::Controller
{
	/// <summary>
	/// Manages process object lifetime, initialization, population & state tracking.
	/// <para> Note that getters are not state tracked. </para>
	/// </summary>
	class ProcessController final
	{
	private:
		Corvus::Object::ProcessObject m_process32{};
		Corvus::Object::ProcessObject m_processNt{};
		HANDLE m_processHandle{ nullptr };

		bool InitializeHandle(
			const DWORD processId,
			const ACCESS_MASK processAccessMask);

		bool DisposeHandle();

		bool InitializeProcessObject32(const DWORD processId);
		bool InitializeProcessObjectNt(const DWORD processId);

	public:
		ProcessController() = default;
		ProcessController(const DWORD processId, const ACCESS_MASK processAccessMask);
		~ProcessController();

		// Delete copy constructor and copy assignment operator
		ProcessController(const ProcessController&) = delete;
		ProcessController& operator=(const ProcessController&) = delete;

		const Corvus::Object::ProcessObject& GetProcessObject32() const noexcept;
		const Corvus::Object::ProcessObject& GetProcessObjectNt() const noexcept;
		const HANDLE& GetProcessHandle() const noexcept;
	};
}