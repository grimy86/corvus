#pragma once
#include "IController.h"
#include "ProcessModel.h"
#include "InjectorModel.h"
#include <MuninnDal.h>

namespace Muninn::Controller
{
	/// <summary>
	/// A state machine for tracking the lifecycle of the process controller itself.
	/// </summary>
	enum class ProcessControllerState : uint8_t
	{
		None,
		Constructed,
		ConstructorError,
		Disposed,
		DisposeError,
		Destructed,
		DestructorError
	};

	/// <summary>
	/// Manages process object lifetime, initialization, population & state tracking.
	/// <para> Note that getters are not state tracked. </para>
	/// </summary>
	class ProcessController final : public IController
	{
	private:
		ProcessControllerState m_state{ ProcessControllerState::None };
		Muninn::Model::ProcessModel m_process{};
		Muninn::Model::InjectorModel m_injector{};

		bool Dispose() noexcept override;

		bool PopulateProcessEntryBasicInfo() noexcept;
		bool PopulateProcessEntryImagePaths() noexcept;
		bool PopulateProcessEntryExtendedInfo() noexcept;
		bool PopulateProcessEntryWindowInfo() noexcept;
		bool PopulateProcessEntryArchitecture() noexcept;

	public:
		ProcessController() noexcept = default;
		ProcessController(const DWORD processId) noexcept;
		ProcessController(
			const DWORD processId,
			const ACCESS_MASK accessMask) noexcept;
		~ProcessController() noexcept;

		const ProcessControllerState& GetState() const noexcept
		{
			return m_state;
		}

		const Muninn::Model::ProcessModel& GetProcess() const noexcept
		{
			return m_process;
		}

		const Muninn::Model::InjectorModel& GetInjector() const noexcept
		{
			return m_injector;
		}

		bool SetProcessId(const DWORD processId) noexcept;
		bool SetProcessHandle(const ACCESS_MASK accessMask) noexcept;
		bool SetInjectorDllPathA(LPCSTR dllPath) noexcept;
		bool SetInjectorDllPathW(LPWSTR dllPath) noexcept;

		bool PopulateProcessEntry() noexcept;
		bool PopulateProcessModuleList() noexcept;
		bool PopulateProcessThreadList() noexcept;
		bool PopulateProcessHandleList() noexcept;

		bool SimpleDLLInjectA() noexcept;
		bool SimpleDLLInjectW() noexcept;

		static DWORD FindProcessId(
			const WCHAR* processName,
			bool& isRunning) noexcept;
	};
}