#include "SystemController.h"

namespace Corvus::Controller
{
	SystemController& SystemController::GetInstance() noexcept
	{
		static SystemController instance;
		return instance;
	}

	BOOL SystemController::UpdateProcessList32()
	{
		if (!m_systemObject.processList32.empty())
			m_systemObject.processList32.clear();

		m_systemObject.processList32 = m_backend32.QueryProcesses();
		return !m_processList32.empty() ? TRUE : FALSE;
	}

	BOOL SystemController::UpdateProcessListNt()
	{
		if (!m_processListNt.empty())
			m_processListNt.clear();

		m_processListNt = m_backendNt.QueryProcesses();
		return !m_processListNt.empty() ? TRUE : FALSE;
	}
}