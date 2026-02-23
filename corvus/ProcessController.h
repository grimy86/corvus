#pragma once
#include "WindowsStructures.h"
#include <Windows.h>
#include <vector>

namespace Corvus::Controller
{
	class ProcessController final
	{
	private:
		ProcessController() = default;
		HANDLE m_processHandle{};
		ACCESS_MASK m_desiredAccessMask{};
		Corvus::Object::ProcessObject m_process{};

	public:
		// Delete copy constructor and copy assignment operator
		ProcessController(const ProcessController&) = delete;
		ProcessController& operator=(const ProcessController&) = delete;
		~ProcessController() = default;
		static ProcessController& GetInstance() noexcept;
	};
}