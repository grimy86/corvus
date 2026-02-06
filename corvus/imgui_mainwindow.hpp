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
	inline std::vector<corvus::process::BackendWin32> g_listW32{ corvus::process::BackendWin32::GetProcessListW32() };
	inline std::vector<corvus::process::BackendNt> g_listNt{ corvus::process::BackendNt::GetProcessListNt() };
	inline DWORD g_selectedPid{};
	inline bool g_IsSeDebugEnabled{ corvus::process::BackendWin32::IsSeDebugPrivilegeEnabledW32() };
	inline int g_threadPriority{ corvus::process::BackendWin32::SetThreadPriorityW32(ABOVE_NORMAL_PRIORITY_CLASS) };

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

	const char* pTableHeaders[]{ "PID", "Name","Path","Priority","ModuleBaseAddress","PEB (Ntdll)","ParentPID",
			"Architecture","WOW64","Protected (Ntdll)","Background (Ntdll)","Secure (Ntdll)","Subsystem (Ntdll)","Visible" };
	const char* tTableHeaders[]{ "ThreadId", "OwnerProcessId", "BasePriority", "StartAddress (Ntdll)", "ThreadState (Ntdll)", "WaitReason (Ntdll)" };
	const char* mTableHeaders[]{ "ProcessId", "Name", "Path", "BaseAddress", "BaseSize", "EntryPoint", "GlobalLoadCount", "ProcessLoadCount" };
	const char* hTableHeaders[]{ "TargetPID (Win32)", "Type", "Name", "Handle", "Flags (Win32)", "Attributes", "AttributesMap", "GrantedAccess", "GrantedAccessMap", "HandleCount (Win32)" };

	inline corvus::process::WindowsProcess* GetSelectedProcess()
	{
		if (!g_selectedPid)
			return nullptr;

		auto& list = g_useNt
			? reinterpret_cast<std::vector<corvus::process::WindowsProcess>&>(g_listNt)
			: reinterpret_cast<std::vector<corvus::process::WindowsProcess>&>(g_listW32);

		for (auto& p : list)
		{
			if (p.GetProcessId() == g_selectedPid)
				return &p;
		}
		return nullptr;
	}

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

	static void DrawProcessRow(corvus::process::WindowsProcess& proc)
	{
		ImGui::PushID(proc.GetProcessId());
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);

		bool selected = (g_selectedPid == proc.GetProcessId());

		if (ImGui::Selectable(proc.GetProcessIdA().c_str(),
			selected,
			ImGuiSelectableFlags_SpanAllColumns))
		{
			g_selectedPid = proc.GetProcessId();

			auto* p = GetSelectedProcess();
			if (p)
			{
				if (p->GetProcessEntryThreads().empty()) p->QueryThreads();
				if (p->GetProcessEntryModules().empty()) p->QueryModules();
				if (p->GetProcessEntryHandles().empty()) p->QueryHandles();
			}
		}

		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(proc.GetProcessEntryNameA().c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(proc.GetProcessEntryImageFilePathA().c_str());
		ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(proc.GetPriorityClassA());
		ImGui::TableSetColumnIndex(4); ImGui::Text("0x%p", (void*)proc.GetModuleBaseAddress());
		ImGui::TableSetColumnIndex(5); ImGui::Text("0x%p", (void*)proc.GetPEBAddress());
		ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", proc.GetParentProcessId());
		ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(proc.GetArchitectureTypeA());
		ImGui::TableSetColumnIndex(8); ImGui::TextUnformatted(proc.IsWow64() ? "True" : "");
		ImGui::TableSetColumnIndex(9); ImGui::TextUnformatted(proc.IsProtectedProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(10); ImGui::TextUnformatted(proc.IsBackgroundProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(11); ImGui::TextUnformatted(proc.IsSecureProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(12); ImGui::TextUnformatted(proc.IsSubsystemProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(13); ImGui::TextUnformatted(proc.HasVisibleWindow() ? "True" : "");
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
		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(corvus::process::WindowsProcess::ToString(module.moduleName).c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(corvus::process::WindowsProcess::ToString(module.modulePath).c_str());
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
		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(corvus::process::WindowsProcess::ToString(handle.typeName).c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(corvus::process::WindowsProcess::ToString(handle.objectName).c_str());
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", handle.handle);
		ImGui::TableSetColumnIndex(4); ImGui::Text("%lu", handle.flags);
		ImGui::TableSetColumnIndex(5); ImGui::Text("%lu", handle.attributes);
		ImGui::TableSetColumnIndex(6); ImGui::Text("%s", corvus::process::WindowsProcess::MapAttributes(handle.attributes));
		ImGui::TableSetColumnIndex(7); ImGui::Text("0x%08X", handle.grantedAccess);
		ImGui::TableSetColumnIndex(8); ImGui::Text("%s", corvus::process::WindowsProcess::MapAccess(handle.typeName, handle.grantedAccess));
		ImGui::TableSetColumnIndex(9); ImGui::Text("%lu", handle.handleCount);
	}

	void DrawProcessTable()
	{
		if (!ImGui::BeginTable("Windows Processes", 14, tFlags)) return;
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

		auto* selected = GetSelectedProcess();
		if (!selected)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		if (selected->GetProcessEntryThreads().empty()) selected->QueryThreads();
		for (const auto& t : selected->GetProcessEntryThreads())
			DrawThreadsRow(t);

		ImGui::EndTable();
	}

	void DrawModulesTable()
	{
		if (!ImGui::BeginTable("Modules", 8, tFlags)) return;
		for (auto header : mTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		auto* selected = GetSelectedProcess();
		if (!selected)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		if (selected->GetProcessEntryModules().empty()) selected->QueryModules();
		for (const auto& m : selected->GetProcessEntryModules())
			DrawModulesRow(m);

		ImGui::EndTable();
	}

	void DrawHandlesTable()
	{
		if (!ImGui::BeginTable("Handles", 10, tFlags)) return;
		for (auto header : hTableHeaders)
			ImGui::TableSetupColumn(header);
		ImGui::TableHeadersRow();

		auto* selected = GetSelectedProcess();
		if (!selected)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}
		if (selected->GetProcessEntryHandles().empty()) selected->QueryHandles();
		for (const auto& h : selected->GetProcessEntryHandles())
			DrawHandlesRow(h);

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
			ImGui::BeginChild("##infobar", ImVec2(0, 80.0f), false);

			if (ImGui::BeginTable("##infobar_table", 2))
			{
				ImGui::TableNextColumn();
				ImVec4 dbgCol = g_IsSeDebugEnabled
					? ImVec4(0, 1, 0, 1)
					: ImVec4(1, 0, 0, 1);

				ImGui::Text("SeDebugPrivilege:");
				ImGui::SameLine();
				ImGui::TextColored(dbgCol, g_IsSeDebugEnabled ? "Enabled" : "Disabled");
				ImGui::Spacing();
				ImGui::Checkbox("Ntdll backend", &g_useNt);
				if (ImGui::Button("Refresh"))
				{
					g_listW32 = corvus::process::BackendWin32::GetProcessListW32();
					g_listNt = corvus::process::BackendNt::GetProcessListNt();

					auto* newSelected = GetSelectedProcess();
					if (!newSelected) g_selectedPid = 0;
				}

				auto* selected = GetSelectedProcess();
				ImGui::TableNextColumn();
				ImVec4 selCol = selected
					? ImVec4(0, 1, 0, 1)
					: ImVec4(1, 0, 0, 1);

				ImGui::Text("Selected:");
				ImGui::SameLine();

				if (selected)
				{
					ImGui::TextColored(
						selCol,
						"%s (%d)",
						selected->GetProcessEntryNameA().c_str(),
						selected->GetProcessId()
					);
					ImGui::Spacing();

					if (ImGui::BeginTable("##procstats", 2,
						ImGuiTableFlags_SizingFixedFit))
					{
						ImGui::TableNextRow();
						ImGui::TableNextColumn(); ImGui::Text("Threads:");
						ImGui::TableNextColumn(); ImGui::Text("%zu", selected->GetProcessEntryThreads().size());
						ImGui::TableNextRow();
						ImGui::TableNextColumn(); ImGui::Text("Modules:");
						ImGui::TableNextColumn(); ImGui::Text("%zu", selected->GetProcessEntryModules().size());
						ImGui::TableNextRow();
						ImGui::TableNextColumn(); ImGui::Text("Handles:");
						ImGui::TableNextColumn(); ImGui::Text("%zu", selected->GetProcessEntryHandles().size());
						ImGui::EndTable();
					}
				}
				else
				{
					ImGui::TextColored(selCol, "None");
				}
				ImGui::EndTable();
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