#pragma once
#include "ProcessStructures.h"
#include <vector>

namespace Corvus::Object
{
	class ProcessObject;
}

namespace Corvus::Data
{
	class IWindowsBackend
	{
	public:
		IWindowsBackend() = default;
		virtual ~IWindowsBackend() = default;
		virtual BOOL QueryProcessInformation(Corvus::Object::ProcessEntry& processEntry) = 0;
		virtual BOOL QueryModuleInformation(Corvus::Object::ProcessEntry& processEntry) = 0;
		virtual BOOL QueryThreadInformation(Corvus::Object::ProcessEntry& processEntry) = 0;
		virtual BOOL QueryHandleInformation(Corvus::Object::ProcessEntry& processEntry) = 0;
		virtual std::vector<Corvus::Object::ModuleEntry> QueryModules(Corvus::Object::ProcessObject& process) = 0;
		virtual std::vector<Corvus::Object::ThreadEntry> QueryThreads(Corvus::Object::ProcessObject& process) = 0;
		virtual std::vector<Corvus::Object::HandleEntry> QueryHandles(Corvus::Object::ProcessObject& process) = 0;
	};
}