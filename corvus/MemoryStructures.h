#pragma once

namespace Corvus::Memory
{
	struct HookInfo
	{
		void* originalFunc;
		void* hookFunc;
		void* returnAddress;
		int overwrittenBytes;
	};
}