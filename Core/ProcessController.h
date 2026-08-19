#pragma once
#include "ControllerBase.h"
#include "ProcessModel.h"
#include <MuninnDal.h>

namespace Muninn::Controller
{
	/// <summary>
    /// Manages process object lifetime, initialization, population and state tracking.
    /// Default constructor leaves state Uninitialized — call SetProcessId/SetProcessHandle
    /// or use a parameterized constructor or static factory.
    /// </summary>
	class ProcessController final : public ControllerBase
	{
	private:
		Muninn::Model::ProcessModel m_process{};
		bool Dispose() noexcept override final;

		// TO DO: Implement both Win32 and NT versions
		bool QueryBasicInfo() noexcept;
		bool QueryImagePaths() noexcept;
		bool QueryExtendedInfo() noexcept;
		bool QueryWindowInfo() noexcept;
		bool QueryArchitecture() noexcept;

	public:
		ProcessController() noexcept = default;
		explicit ProcessController(const DWORD processId) noexcept;
		explicit ProcessController(const DWORD processId, const ACCESS_MASK accessMask) noexcept;
		~ProcessController() noexcept override;

		const Muninn::Model::ProcessModel& GetProcess() const noexcept;
		bool SetProcessId(const DWORD processId) noexcept;
		bool SetProcessHandle(const ACCESS_MASK accessMask) noexcept;

		bool RefreshProcessEntry() noexcept;
		bool RefreshModuleList() noexcept;
		bool RefreshThreadList() noexcept;
		bool RefreshHandleList() noexcept;

		static ProcessController FromName(
			const WCHAR* const processName,
			bool& isRunning,
			const ACCESS_MASK accessMask = PROCESS_ALL_ACCESS) noexcept;

		static ProcessController FromName(
			const std::wstring& processName,
			bool& isRunning,
			const ACCESS_MASK accessMask = PROCESS_ALL_ACCESS) noexcept;
	};
}