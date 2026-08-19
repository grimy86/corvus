#pragma once
#include "ControllerBase.h"
#include "InjectorModel.h"
#include "ProcessController.h"
#include <MuninnDal.h>

namespace Muninn::Controller
{
	class InjectorController final : public ControllerBase
	{
	private:
		Muninn::Model::InjectorModel m_injector{};
		bool Dispose() noexcept override final;

		bool ExecuteLoadLibrary(const ProcessController& target) noexcept;
		bool ExecuteManualMap(const ProcessController& target) noexcept;
		bool ExecuteReflective(const ProcessController& target) noexcept;

	public:
		InjectorController() noexcept = default;
		explicit InjectorController(const WCHAR* dllPath) noexcept;
		explicit InjectorController(const std::wstring& dllPath) noexcept;
		~InjectorController() noexcept override;

		const Muninn::Model::InjectorModel& GetInjector() const noexcept;
		bool SetDllPath(const WCHAR* dllPath) noexcept;
		bool SetDllPath(const std::wstring& dllPath) noexcept;
		bool SetTechnique(Muninn::Model::InjectionTechnique technique) noexcept;
		bool SetVector(Muninn::Model::InjectionVector vector) noexcept;

		bool Inject(const ProcessController& target) noexcept;
		bool Eject(const ProcessController& target) noexcept;
	};
}