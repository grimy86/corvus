#include <imgui.h>
#include "process.hpp"

namespace corvus::imgui
{
	enum class View
	{
		Process,
		Threads,
		Modules,
		Handles
	};

	enum class Backend
	{
		Win32,
		Nt
	};

	inline ImFont* g_mainFont{ nullptr };
	inline View g_currentView{ View::Process };
	inline Backend g_currentBackend{ Backend::Win32 };
	inline std::vector<corvus::process::WindowsProcessWin32> g_procListW32{};
	inline std::vector<corvus::process::WindowsProcessNt> g_procListNt{};
	inline bool g_win32Loaded{ false };
	inline bool g_ntLoaded{ false };
	inline const corvus::process::WindowsProcessBase* g_selectedProcess{};
	inline DWORD g_selectedProcessId{};
	inline char g_processSearch[128]{};

	void SetStyle(ImGuiStyle& style, const float mainScale)
	{
		style.ScaleAllSizes(mainScale);
		style.FontScaleDpi = mainScale;
	}

	void RefreshProcessList()
	{
		if (g_currentBackend == Backend::Win32)
		{
			if (!g_win32Loaded)
			{
				g_procListW32 = corvus::process::WindowsProcessWin32::GetProcessListW32();
				g_win32Loaded = true;
			}
		}
		else
		{
			if (!g_ntLoaded)
			{
				g_procListNt = corvus::process::WindowsProcessNt::GetProcessListNt();
				g_ntLoaded = true;
			}
		}
	}

	void DrawNavBar();
	void DrawContentView();
	void DrawProcessTable();
	void DrawModulesTable();
	void DrawThreadsTable();
	void DrawHandlesTable();

	void ShowMainWindow()
	{
		ImGui::PushFont(g_mainFont);

		ImGuiViewport* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->Pos, ImGuiCond_Always);
		ImGui::SetNextWindowSize(viewport->Size, ImGuiCond_Always);

		static constexpr ImGuiWindowFlags wndFlags{
			ImGuiWindowFlags_NoTitleBar |
			ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings
		};

		if (ImGui::Begin("##mainWindow", nullptr, wndFlags))
		{
			// First refresh
			static bool initialized = false;
			if (!initialized)
			{
				corvus::process::WindowsProcessWin32::EnableSeDebugPrivilegeW32();
				RefreshProcessList();
				initialized = true;
			}

			// --- Debug info ---
			bool seDebugEnabled = corvus::process::WindowsProcessBase::IsSeDebugPrivilegeEnabled();
			ImVec4 col = seDebugEnabled ? ImVec4(0, 1, 0, 1) : ImVec4(1, 0, 0, 1);

			// Counts
			size_t processCount = (g_currentBackend == Backend::Win32) ? g_procListW32.size() : g_procListNt.size();
			size_t moduleCount = g_selectedProcess ? g_selectedProcess->GetModules().size() : 0;
			size_t threadCount = g_selectedProcess ? g_selectedProcess->GetThreads().size() : 0;
			size_t handleCount = g_selectedProcess ? g_selectedProcess->GetHandles().size() : 0;

			// --- Start 3 main columns ---
			ImGui::Columns(3, nullptr, false);

			// --- Column 1: SeDebugPrivilege + Backend toggle ---
			{
				ImGui::Text("SeDebugPrivilege:"); ImGui::SameLine();
				ImGui::TextColored(col, "\xE2\x97\x8F"); // ●

				bool useNt = (g_currentBackend == Backend::Nt);
				ImGui::TextColored(col, "Toggle Ntdll backend"); ImGui::SameLine();
				ImGui::Checkbox("##backend", &useNt);

				if (useNt != (g_currentBackend == Backend::Nt))
				{
					g_currentBackend = useNt ? Backend::Nt : Backend::Win32;
					RefreshProcessList();
				}
				ImGui::NextColumn();
			}

			// --- Column 2: Processes + Selected Process ---
			{
				ImGui::Text("Processes:"); ImGui::SameLine();
				ImGui::TextColored(col, "%zu", processCount);

				ImGui::Text("Selected:"); ImGui::SameLine();
				ImGui::TextColored(
					col,
					"%s",
					g_selectedProcess
					? corvus::process::WindowsProcessBase::ToString(g_selectedProcess->GetName()).c_str()
					: "No process selected"
				);

				ImGui::NextColumn();
			}

			// --- Column 3: Modules + Threads + Handles ---
			{
				ImGui::Text("Modules:"); ImGui::SameLine();
				ImGui::TextColored(col, "%zu", moduleCount);

				ImGui::Text("Threads:"); ImGui::SameLine();
				ImGui::TextColored(col, "%zu", threadCount);

				ImGui::Text("Handles:"); ImGui::SameLine();
				ImGui::TextColored(col, "%zu", handleCount);

				ImGui::NextColumn();
			}

			ImGui::Columns(1); // back to single column

			// Search bar below all, left-aligned with padding
			float padding = 2.5f; // space from edges
			float fullWidth = ImGui::GetContentRegionAvail().x - padding * 2.0f;

			ImGui::Text("Search:"); ImGui::SameLine();
			ImGui::SetNextItemWidth(fullWidth - ImGui::GetItemRectSize().x);
			ImGui::InputText("##search", g_processSearch, IM_ARRAYSIZE(g_processSearch));

			// left nav bar
			ImGui::BeginChild(
				"##navbar",
				ImVec2(150.0f, 0),
				true);
			DrawNavBar();
			ImGui::EndChild();

			// right content view
			ImGui::SameLine();
			ImGui::BeginChild(
				"##contentview",
				ImVec2(0, 0),
				false);
			DrawContentView();
			ImGui::EndChild();
		}

		ImGui::PopFont();
		ImGui::End();
	}

	void DrawNavBar()
	{
		ImGuiTreeNodeFlags flags =
			ImGuiTreeNodeFlags_DefaultOpen |
			ImGuiTreeNodeFlags_Framed |
			ImGuiTreeNodeFlags_DrawLinesFull |
			(g_currentView == View::Process ? ImGuiTreeNodeFlags_Selected : 0);

		bool open = ImGui::TreeNodeEx("Process", flags);
		if (ImGui::IsItemClicked()) g_currentView = View::Process;

		if (open)
		{
			ImGui::Indent();

			if (ImGui::Selectable("Threads", g_currentView == View::Threads))
				g_currentView = View::Threads;

			if (ImGui::Selectable("Modules", g_currentView == View::Modules))
				g_currentView = View::Modules;

			if (ImGui::Selectable("Handles", g_currentView == View::Handles))
				g_currentView = View::Handles;

			ImGui::Unindent();
			ImGui::TreePop();
		}
	}

	void DrawContentView()
	{
		switch (g_currentView)
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
	}

	template <typename TProcess>
	static void DrawProcessRow(const TProcess& proc)
	{
		std::string name = corvus::process::WindowsProcessBase::ToString(proc.GetName());
		bool selected = (proc.GetProcessId() == g_selectedProcessId);

		ImGui::PushID(proc.GetProcessId());
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);

		// Color coding
		ImVec4 col = proc.IsProtectedProcess() ? ImVec4(1, 0, 0, 1) :
			proc.IsWow64() ? ImVec4(1, 1, 0, 1) :
			proc.IsBackgroundProcess() ? ImVec4(0.5f, 0.5f, 1, 1) : ImVec4(1, 1, 1, 1);

		if (ImGui::Selectable(name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
		{
			g_selectedProcessId = proc.GetProcessId();
			g_selectedProcess = &proc;
		}

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(proc.GetImageFilePath()).c_str());
		ImGui::TableSetColumnIndex(2);
		ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(proc.GetPriorityClass()).c_str());
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", (void*)proc.GetModuleBaseAddress());
		ImGui::TableSetColumnIndex(4); ImGui::Text("0x%p", (void*)proc.GetPEBAddress());
		ImGui::TableSetColumnIndex(5); ImGui::Text("%lu", proc.GetProcessId());
		ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", proc.GetParentProcessId());
		ImGui::TableSetColumnIndex(7); ImGui::Text("%ld", proc.GetBasePriority());
		ImGui::TableSetColumnIndex(8); ImGui::TextUnformatted(corvus::process::WindowsProcessBase::ToString(proc.GetArchitectureType()));
		ImGui::TableSetColumnIndex(9); ImGui::TextUnformatted(proc.IsWow64() ? "True" : "");
		ImGui::TableSetColumnIndex(10); ImGui::TextUnformatted(proc.IsProtectedProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(11); ImGui::TextUnformatted(proc.IsBackgroundProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(12); ImGui::TextUnformatted(proc.IsSecureProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(13); ImGui::TextUnformatted(proc.IsSubsystemProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(14); ImGui::TextUnformatted(proc.HasVisibleWindow() ? "True" : "");

		ImGui::PopID();
	}

	static void DrawModulesRow(const corvus::process::ModuleEntry& module)
	{
		ImGui::TableNextRow();

		ImGui::TableSetColumnIndex(0);
		ImGui::TextUnformatted(
			corvus::process::WindowsProcessBase::ToString(module.moduleName).c_str()
		);

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(
			corvus::process::WindowsProcessBase::ToString(module.modulePath).c_str()
		);

		ImGui::TableSetColumnIndex(2);
		ImGui::Text("0x%p", (void*)module.baseAddress);

		ImGui::TableSetColumnIndex(3);
		ImGui::Text("%zu", module.moduleBaseSize);

		ImGui::TableSetColumnIndex(4);
		ImGui::Text("0x%p", module.entryPoint);

		ImGui::TableSetColumnIndex(5);
		ImGui::Text("%lu", module.processId);

		ImGui::TableSetColumnIndex(6);
		ImGui::Text("%lu", module.globalLoadCount);

		ImGui::TableSetColumnIndex(7);
		ImGui::Text("%lu", module.processLoadCount);
	}

	template <typename TThread>
	static void DrawThreadsRow(const TThread& thread)
	{
		ImGui::TableNextRow();

		ImGui::TableSetColumnIndex(0);
		ImGui::Text("%lu", thread.threadId);

		ImGui::TableSetColumnIndex(1);
		ImGui::Text("%lu", thread.ownerProcessId);

		ImGui::TableSetColumnIndex(2);
		ImGui::Text("%ld", thread.basePriority);

		ImGui::TableSetColumnIndex(3);
		ImGui::Text("%ld", thread.deltaPriority);

		ImGui::TableSetColumnIndex(4);
		ImGui::Text("%lu", thread.flags);

		ImGui::TableSetColumnIndex(5);
		ImGui::Text("0x%p", thread.startAddress);

		ImGui::TableSetColumnIndex(6);
		ImGui::Text("%u", static_cast<uint32_t>(thread.threadState));

		ImGui::TableSetColumnIndex(7);
		ImGui::Text("%u", static_cast<uint32_t>(thread.waitReason));
	}

	template <typename THandle>
	static void DrawHandlesRow(const THandle& handle)
	{
		ImGui::TableNextRow();

		ImGui::TableSetColumnIndex(0);
		ImGui::TextUnformatted(
			corvus::process::WindowsProcessBase::ToString(handle.typeName).c_str());

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(
			corvus::process::WindowsProcessBase::ToString(handle.objectName).c_str());

		ImGui::TableSetColumnIndex(2);
		ImGui::Text("0x%p", handle.handle);

		ImGui::TableSetColumnIndex(3);
		ImGui::Text("%lu", handle.flags);

		ImGui::TableSetColumnIndex(4);
		ImGui::TextUnformatted(
			corvus::process::WindowsProcessBase::ToString(handle.objectType));

		ImGui::TableSetColumnIndex(5);
		ImGui::Text("%lu", handle.attributes);

		ImGui::TableSetColumnIndex(6);
		ImGui::Text("0x%08X", handle.grantedAccess);

		ImGui::TableSetColumnIndex(7);
		ImGui::Text("%lu", handle.handleCount);

		ImGui::TableSetColumnIndex(8);
		ImGui::Text("%u", handle.objectTypeIndex);
	}

	void DrawProcessTable()
	{
		ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8.0f, 6.0f));
		if (!ImGui::BeginTable("Windows Processes", 15,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollX |
			ImGuiTableFlags_NoHostExtendX |
			ImGuiTableFlags_SizingFixedFit))
			return;

		ImGui::TableSetupColumn("Name");
		ImGui::TableSetupColumn("ImageFilePath");
		ImGui::TableSetupColumn("PriorityClass");
		ImGui::TableSetupColumn("ModuleBaseAddress");
		ImGui::TableSetupColumn("PEBAddress (Ntdll)");
		ImGui::TableSetupColumn("ProcessId");
		ImGui::TableSetupColumn("ParentProcessId");
		ImGui::TableSetupColumn("BasePriority (Ntdll)");
		ImGui::TableSetupColumn("ArchitectureType");
		ImGui::TableSetupColumn("IsWow64");
		ImGui::TableSetupColumn("IsProtectedProcess (Ntdll)");
		ImGui::TableSetupColumn("IsBackgroundProcess (Ntdll)");
		ImGui::TableSetupColumn("IsSecureProcess (Ntdll)");
		ImGui::TableSetupColumn("IsSubsystemProcess (Ntdll)");
		ImGui::TableSetupColumn("HasVisibleWindow");
		ImGui::TableHeadersRow();

		if (g_currentBackend == Backend::Win32)
		{
			for (const auto& proc : g_procListW32)
			{
				if (strlen(g_processSearch) == 0 ||
					corvus::process::WindowsProcessBase::ToString(proc.GetName()).find(g_processSearch) != std::string::npos)
					DrawProcessRow(proc);
			}
		}
		else
		{
			for (const auto& proc : g_procListNt)
			{
				if (strlen(g_processSearch) == 0 ||
					corvus::process::WindowsProcessBase::ToString(proc.GetName()).find(g_processSearch) != std::string::npos)
					DrawProcessRow(proc);
			}
		}

		ImGui::PopStyleVar();
		ImGui::EndTable();
	}

	void DrawModulesTable()
	{
		if (!ImGui::BeginTable("Modules", 9,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollX |
			ImGuiTableFlags_NoHostExtendX |
			ImGuiTableFlags_SizingFixedFit))
			return;

		ImGui::TableSetupColumn("Name");
		ImGui::TableSetupColumn("Path");
		ImGui::TableSetupColumn("Size");
		ImGui::TableSetupColumn("BaseAddress");
		ImGui::TableSetupColumn("BaseSize");
		ImGui::TableSetupColumn("EntryPoint");
		ImGui::TableSetupColumn("ProcessId");
		ImGui::TableSetupColumn("GlobalLoadCount");
		ImGui::TableSetupColumn("ProcessLoadCount");
		ImGui::TableHeadersRow();

		if (!g_selectedProcessId)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}

		if (g_currentBackend == Backend::Win32)
		{
			for (const auto& proc : g_procListW32)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& mod : proc.GetModules())
					DrawModulesRow(mod);

				break; // important
			}
		}
		else
		{
			for (const auto& proc : g_procListNt)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& mod : proc.GetModules())
					DrawModulesRow(mod);

				break;
			}
		}

		ImGui::EndTable();
	}

	void DrawThreadsTable()
	{
		if (!ImGui::BeginTable("Threads", 8,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollX |
			ImGuiTableFlags_NoHostExtendX |
			ImGuiTableFlags_SizingFixedFit))
			return;

		ImGui::TableSetupColumn("ThreadId");
		ImGui::TableSetupColumn("OwnerProcessId");
		ImGui::TableSetupColumn("BasePriority");
		ImGui::TableSetupColumn("DeltaPriority");
		ImGui::TableSetupColumn("Flags");
		ImGui::TableSetupColumn("StartAddress");
		ImGui::TableSetupColumn("ThreadState");
		ImGui::TableSetupColumn("WaitReason");
		ImGui::TableHeadersRow();

		if (!g_selectedProcessId)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}

		if (g_currentBackend == Backend::Win32)
		{
			for (const auto& proc : g_procListW32)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& thread : proc.GetThreads())
					DrawThreadsRow(thread);

				break;
			}
		}
		else
		{
			for (const auto& proc : g_procListNt)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& thread : proc.GetThreads())
					DrawThreadsRow(thread);

				break;
			}
		}

		ImGui::EndTable();
	}

	void DrawHandlesTable()
	{
		if (!ImGui::BeginTable("Handles", 9,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollX |
			ImGuiTableFlags_NoHostExtendX |
			ImGuiTableFlags_SizingFixedFit))
			return;

		ImGui::TableSetupColumn("Type");
		ImGui::TableSetupColumn("Name");
		ImGui::TableSetupColumn("Handle");
		ImGui::TableSetupColumn("Flags");
		ImGui::TableSetupColumn("ObjectType");
		ImGui::TableSetupColumn("Attributes");
		ImGui::TableSetupColumn("GrantedAccess");
		ImGui::TableSetupColumn("HandleCount");
		ImGui::TableSetupColumn("ObjectTypeIndex");
		ImGui::TableHeadersRow();

		if (!g_selectedProcessId)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted("No process selected");
			ImGui::EndTable();
			return;
		}

		if (g_currentBackend == Backend::Win32)
		{
			for (const auto& proc : g_procListW32)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& handle : proc.GetHandles())
					DrawHandlesRow(handle);

				break;
			}
		}
		else
		{
			for (const auto& proc : g_procListNt)
			{
				if (proc.GetProcessId() != g_selectedProcessId)
					continue;

				for (const auto& handle : proc.GetHandles())
					DrawHandlesRow(handle);

				break;
			}
		}

		ImGui::EndTable();
	}
}