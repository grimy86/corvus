#pragma once
#include "process.hpp"
#include <imgui.h>

namespace corvus::imgui
{
	enum class View
	{
		Process,
		Threads,
		Modules,
		Handles
	};

	inline View g_view{ View::Process };
	inline bool g_useNt{ false };
	inline std::vector<corvus::process::WindowsProcessWin32> g_listW32{ corvus::process::WindowsProcessWin32::GetProcessListW32() };
	inline std::vector<corvus::process::WindowsProcessNt> g_listNt{ corvus::process::WindowsProcessNt::GetProcessListNt() };
	inline corvus::process::WindowsProcessBase* g_selectedItem;
	inline bool g_IsSeDebugEnabled{ corvus::process::WindowsProcessWin32::IsSeDebugPrivilegeEnabledW32() };
	inline int g_threadPriority{ corvus::process::WindowsProcessWin32::SetThreadPriorityW32(ABOVE_NORMAL_PRIORITY_CLASS) };

	constexpr ImGuiWindowFlags wndFlags{
			ImGuiWindowFlags_NoTitleBar |
			ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings };

	constexpr ImGuiTreeNodeFlags tnFlags{
		ImGuiTreeNodeFlags_DefaultOpen |
		ImGuiTreeNodeFlags_Framed |
		ImGuiTreeNodeFlags_Leaf
	};

	constexpr ImGuiTableFlags tFlags{
		ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Borders |
		ImGuiTableFlags_ScrollX |
		ImGuiTableFlags_NoHostExtendX |
		ImGuiTableFlags_SizingFixedFit };

	const char* pTableHeaders[]{ "PID", "Name","Path","Priority","Base","PEB (Ntdll)","ParentPID","BasePriority (Ntdll)",
			"Arch","WOW64","Protected (Ntdll)","Background (Ntdll)","Secure (Ntdll)","Subsystem (Ntdll)","Visible" };
	const char* tTableHeaders[]{ "ThreadId", "OwnerProcessId", "BasePriority", "StartAddress (Ntdll)", "ThreadState (Ntdll)", "WaitReason (Ntdll)" };
	const char* mTableHeaders[]{ "ProcessId", "Name", "Path", "BaseAddress", "BaseSize", "EntryPoint", "GlobalLoadCount", "ProcessLoadCount" };
	const char* hTableHeaders[]{ "TargetPID", "Type", "Name", "Handle", "Flags", "Attributes", "GrantedAccess", "DecodedGrantedAccess", "HandleCount" };

	void DrawNavBar()
	{
		bool open = ImGui::TreeNodeEx("Process", tnFlags);
		if (ImGui::IsItemClicked()) g_view = View::Process;

		if (open)
		{
			ImGui::Indent();

			if (ImGui::Selectable("Threads", g_view == View::Threads))
				g_view = View::Threads;

			if (ImGui::Selectable("Modules", g_view == View::Modules))
				g_view = View::Modules;

			if (ImGui::Selectable("Handles", g_view == View::Handles))
				g_view = View::Handles;

			ImGui::Unindent();
			ImGui::TreePop();
		}
	}

	static void DrawProcessRow(corvus::process::WindowsProcessBase& proc)
	{
		ImGui::PushID(proc.GetProcessId());
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);

		bool selected = (g_selectedItem == &proc);

		if (ImGui::Selectable(proc.GetProcessIdA().c_str(),
			selected,
			ImGuiSelectableFlags_SpanAllColumns))
		{
			g_selectedItem = &proc;
		}

		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(proc.GetNameA().c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(proc.GetImageFilePathA().c_str());
		ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(proc.GetPriorityClassA());
		ImGui::TableSetColumnIndex(4); ImGui::Text("0x%p", (void*)proc.GetModuleBaseAddress());
		ImGui::TableSetColumnIndex(5); ImGui::Text("0x%p", (void*)proc.GetPEBAddress());
		ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", proc.GetParentProcessId());
		ImGui::TableSetColumnIndex(7); ImGui::Text("%ld", proc.GetBasePriority());
		ImGui::TableSetColumnIndex(8); ImGui::TextUnformatted(proc.GetArchitectureTypeA());
		ImGui::TableSetColumnIndex(9); ImGui::TextUnformatted(proc.IsWow64() ? "True" : "");
		ImGui::TableSetColumnIndex(10); ImGui::TextUnformatted(proc.IsProtectedProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(11); ImGui::TextUnformatted(proc.IsBackgroundProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(12); ImGui::TextUnformatted(proc.IsSecureProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(13); ImGui::TextUnformatted(proc.IsSubsystemProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(14); ImGui::TextUnformatted(proc.HasVisibleWindow() ? "True" : "");
		ImGui::PopID();
	}

	static void DrawThreadsRow(const corvus::process::ThreadEntry& thread)
	{
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", thread.threadId);
		ImGui::TableSetColumnIndex(1); ImGui::Text("%lu", thread.ownerProcessId);
		ImGui::TableSetColumnIndex(2); ImGui::Text("%ld", thread.basePriority);
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", thread.startAddress);
		ImGui::TableSetColumnIndex(4); ImGui::Text("%u", static_cast<uint32_t>(thread.threadState));
		ImGui::TableSetColumnIndex(5); ImGui::Text("%u", static_cast<uint32_t>(thread.waitReason));
	}

	static void DrawModulesRow(const corvus::process::ModuleEntry& module)
	{
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", module.processId);
		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(module.moduleName).c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(module.modulePath).c_str());
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", (void*)module.baseAddress);
		ImGui::TableSetColumnIndex(4); ImGui::Text("%zu", module.moduleBaseSize);
		ImGui::TableSetColumnIndex(5); ImGui::Text("0x%p", module.entryPoint);
		ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", module.globalLoadCount);
		ImGui::TableSetColumnIndex(7); ImGui::Text("%lu", module.processLoadCount);
	}

	static void DrawHandlesRow(const corvus::process::HandleEntry& handle)
	{
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", handle.targetProcessId);
		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(handle.typeName).c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(handle.objectName).c_str());
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", handle.handle);
		ImGui::TableSetColumnIndex(4); ImGui::Text("%lu", handle.flags);
		ImGui::TableSetColumnIndex(5); ImGui::Text("%lu", handle.attributes);
		ImGui::TableSetColumnIndex(6); ImGui::Text("0x%08X", handle.grantedAccess);
		ImGui::TableSetColumnIndex(7); ImGui::Text("%s", corvus::process::WindowsProcessBase::ToString(handle.pssObjectType, handle.grantedAccess));
		ImGui::TableSetColumnIndex(8); ImGui::Text("%lu", handle.handleCount);
	}

	void DrawProcessTable()
	{
		if (!ImGui::BeginTable("Windows Processes", 15, tFlags)) return;
		for (auto header : pTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		if (!g_useNt)
			for (auto& p : g_listW32) DrawProcessRow(p);
		else
			for (auto& p : g_listNt) DrawProcessRow(p);

		ImGui::EndTable();
	}

	void DrawThreadsTable()
	{
		if (!ImGui::BeginTable("Threads", 6, tFlags)) return;
		for (auto header : tTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		if (!g_selectedItem)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		else
		{
			if (g_selectedItem->GetThreads().size() <= 0)
			{
				g_selectedItem->QueryThreads();
			}
			if (!g_useNt)
			{
				for (const auto& thread : g_selectedItem->GetThreads())
					DrawThreadsRow(thread);
			}
			else
			{
				for (const auto& thread : g_selectedItem->GetThreads())
					DrawThreadsRow(thread);
			}
		}

		ImGui::EndTable();
	}

	void DrawModulesTable()
	{
		if (!ImGui::BeginTable("Modules", 8, tFlags)) return;
		for (auto header : mTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		if (!g_selectedItem)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		else
		{
			if (g_selectedItem->GetModules().size() <= 0)
			{
				g_selectedItem->QueryModules();
			}
			if (!g_useNt)
			{
				for (const auto& module : g_selectedItem->GetModules())
					DrawModulesRow(module);
			}
			else
			{
				for (const auto& module : g_selectedItem->GetModules())
					DrawModulesRow(module);
			}
		}

		ImGui::EndTable();
	}

	void DrawHandlesTable()
	{
		if (!ImGui::BeginTable("Handles", 9, tFlags)) return;
		for (auto header : hTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		if (!g_selectedItem)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		else
		{
			if (g_selectedItem->GetHandles().size() <= 0)
			{
				g_selectedItem->QueryHandles();
			}
			if (!g_useNt)
			{
				for (const auto& handle : g_selectedItem->GetHandles())
					DrawHandlesRow(handle);
			}
			else
			{
				for (const auto& handle : g_selectedItem->GetHandles())
					DrawHandlesRow(handle);
			}
		}

		ImGui::EndTable();
	}

	void ShowMainWindow()
	{
		ImGuiViewport* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->Pos, ImGuiCond_Always);
		ImGui::SetNextWindowSize(viewport->Size, ImGuiCond_Always);

		if (ImGui::Begin("##mainWindow", nullptr, wndFlags))
		{
			// INFOBAR
			ImGui::BeginChild("##infobar", ImVec2(0, 35.0f), false);
			{
				ImGui::Columns(2, nullptr, false);

				// Left side
				ImVec4 dbgCol = g_IsSeDebugEnabled
					? ImVec4(0, 1, 0, 1)
					: ImVec4(1, 0, 0, 1);

				ImGui::Text("SeDebugPrivilege:");
				ImGui::SameLine();
				ImGui::PushStyleColor(ImGuiCol_Text, dbgCol);
				ImGui::Bullet();
				ImGui::PopStyleColor();
				ImGui::NewLine();
				ImGui::Checkbox("Ntdll backend", &g_useNt);
				ImGui::NextColumn();

				// Right side
				ImVec4 selCol = g_selectedItem
					? ImVec4(0, 1, 0, 1)
					: ImVec4(1, 0, 0, 1);

				ImGui::Text("Selected:");
				ImGui::SameLine();

				if (g_selectedItem)
				{
					ImGui::TextColored(selCol, "%s (%d)",
						g_selectedItem->GetNameA().c_str(),
						g_selectedItem->GetProcessId());
				}
				else
				{
					ImGui::TextColored(selCol, "None");
				}

				ImGui::Columns(1);
			}
			ImGui::EndChild();

			// NAVBAR
			ImGui::BeginChild("##navbar", ImVec2(150.0f, 0), true);
			DrawNavBar();
			ImGui::EndChild();

			// CONTENT VIEW
			ImGui::SameLine();
			ImGui::BeginChild("##contentview", ImVec2(0, 0), false);

			switch (g_view)
			{
			case View::Process:
				DrawProcessTable();
				break;
			case View::Threads:
				DrawThreadsTable();
				break;
			case View::Modules:
				DrawModulesTable();
				break;
			case View::Handles:
				DrawHandlesTable();
				break;
			default:
				DrawProcessTable();
				break;
			}
			ImGui::EndChild();
		}
		ImGui::End();
	}
}