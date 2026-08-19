#include "InjectorController.h"

namespace Muninn::Controller
{
#pragma region Constructor, Destructor & Dispose

	InjectorController::InjectorController(
		const WCHAR* dllPath) noexcept
	{
		if (!SetDllPath(dllPath))
			SetState(ControllerState::ConstructorError);
		else
			SetState(ControllerState::Initialized);
	}

	InjectorController::InjectorController(
		const std::wstring& dllPath) noexcept
	{
		if (!SetDllPath(dllPath))
			SetState(ControllerState::ConstructorError);
		else
			SetState(ControllerState::Initialized);
	}

	InjectorController::~InjectorController() noexcept
	{
		if (!Dispose())
		{
			SetState(ControllerState::DestructorError);
		}
	}

	bool ProcessController::Dispose() noexcept
	{
		/*
		if (!DAL_IsValidHandle(m_process.processHandle))
		{
			SetState(ControllerState::Disposed);
			return true;
		}

		if (!NT_SUCCESS(DAL_Nt_CloseHandle(
			m_process.processHandle)))
		{
			SetState(ControllerState::DisposeError);
			return false;
		}

		m_process.processHandle = nullptr;
		SetState(ControllerState::Disposed);
		*/

		return true;
	}
#pragma endregion

#pragma region Private Methods

	bool InjectorController::ExecuteLoadLibrary(const ProcessController& target) noexcept
	{
		// To be implemented
	}

	bool InjectorController::ExecuteManualMap(const ProcessController& target) noexcept
	{
		// To be implemented
	}

	bool InjectorController::ExecuteReflective(const ProcessController& target) noexcept
	{
		// To be implemented
	}

#pragma endregion

#pragma region Public Getters & Setters
	const Muninn::Model::InjectorModel& InjectorController::GetInjector() const noexcept
	{
		return m_injector;
	}

	bool InjectorController::SetDllPath(const WCHAR* dllPath) noexcept
	{
		if (dllPath == nullptr)
			return false;

		m_injector.DllPath = dllPath;
		return true;
	}

	bool InjectorController::SetDllPath(const std::wstring& dllPath) noexcept
	{
		if (SetDllPath(dllPath.c_str()))
			return true;
		else
			return false;
	}

	bool InjectorController::SetTechnique(Muninn::Model::InjectionTechnique technique) noexcept
	{
		if (technique == Muninn::Model::InjectionTechnique::Unknown)
			return false;

		m_injector.Technique = technique;
		return true;
	}

	bool InjectorController::SetVector(Muninn::Model::InjectionVector vector) noexcept
	{
		if (vector == Muninn::Model::InjectionVector::Unknown)
			return false;

		m_injector.Vector = vector;
		return true;
	}

#pragma endregion

#pragma region Public Methods
	bool InjectorController::Inject(const ProcessController& target) noexcept
	{
		if (!DAL_IsValidProcessId(target.GetProcess().processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(target.GetProcess().processHandle))
			return false;

		switch (m_injector.Technique)
		{
		case Muninn::Model::InjectionTechnique::LoadLib :
			return ExecuteLoadLibrary(target);
			break;
		case Muninn::Model::InjectionTechnique::ManualMap:
			return ExecuteManualMap(target);
			break;
		case Muninn::Model::InjectionTechnique::Reflective:
			return ExecuteReflective(target);
			break;
		}
	}

	bool InjectorController::Eject(const ProcessController& target) noexcept
	{

	}

#pragma endregion
}