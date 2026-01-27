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
	inline bool g_win32Loaded = false;
	inline bool g_ntLoaded = false;

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
	void DrawThreadsTable();
	void DrawModulesTable();
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
				RefreshProcessList();
				initialized = true;
			}

			// Backend toggle
			bool useNt = (g_currentBackend == Backend::Nt);
			if (ImGui::Checkbox(" Use NTDLL backend", &useNt))
			{
				g_currentBackend = useNt ? Backend::Nt : Backend::Win32;
				RefreshProcessList();
			}
			ImGui::Separator();

			// left nav bar
			ImGui::BeginChild(
				"##navbar",
				ImVec2(250.0f, 0),
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
		ImGuiTreeNodeFlags flags{
			ImGuiTreeNodeFlags_DefaultOpen |
			ImGuiTreeNodeFlags_Framed |
			ImGuiTreeNodeFlags_DrawLinesFull |
			(g_currentView == View::Process ?
				ImGuiTreeNodeFlags_Selected : 0) };

		bool bProcess{ ImGui::TreeNodeEx("Process", flags) };

		if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen())
		{
			g_currentView = View::Process;
		}

		if (bProcess)
		{
			if (ImGui::Selectable("Threads", g_currentView == View::Threads))
				g_currentView = View::Threads;

			if (ImGui::Selectable("Modules", g_currentView == View::Modules))
				g_currentView = View::Modules;

			if (ImGui::Selectable("Handles", g_currentView == View::Handles))
				g_currentView = View::Handles;

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
		ImGui::TableNextRow();

		ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(proc.GetNameUTF8().c_str());
		ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(proc.GetImageFilePathUTF8().c_str());
		ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(proc.GetPriorityClassUTF8().c_str());
		ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", (void*)proc.GetModuleBaseAddress());
		ImGui::TableSetColumnIndex(4); ImGui::Text("0x%p", (void*)proc.GetPEBAddress());
		ImGui::TableSetColumnIndex(5); ImGui::Text("%lu", proc.GetProcessId());
		ImGui::TableSetColumnIndex(6); ImGui::Text("%ld", proc.GetBasePriority());
		ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(proc.GetArchitectureTypeUTF8().c_str());
		ImGui::TableSetColumnIndex(8); ImGui::TextUnformatted(proc.IsWow64() ? "True" : "");
		ImGui::TableSetColumnIndex(9); ImGui::TextUnformatted(proc.IsProtectedProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(10); ImGui::TextUnformatted(proc.IsBackgroundProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(11); ImGui::TextUnformatted(proc.IsSecureProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(12); ImGui::TextUnformatted(proc.IsSubsystemProcess() ? "True" : "");
		ImGui::TableSetColumnIndex(13); ImGui::TextUnformatted(proc.HasVisibleWindow() ? "True" : "");
	}

	void DrawProcessTable()
	{
		if (!ImGui::BeginTable("Windows Processes", 14,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable))
			return;

		ImGui::TableSetupColumn("Name");
		ImGui::TableSetupColumn("ImageFilePath");
		ImGui::TableSetupColumn("PriorityClass");
		ImGui::TableSetupColumn("ModuleBaseAddress");
		ImGui::TableSetupColumn("PEBAddress");
		ImGui::TableSetupColumn("ProcessId");
		ImGui::TableSetupColumn("BasePriority");
		ImGui::TableSetupColumn("ArchitectureType");
		ImGui::TableSetupColumn("IsWow64");
		ImGui::TableSetupColumn("IsProtectedProcess");
		ImGui::TableSetupColumn("IsBackgroundProcess");
		ImGui::TableSetupColumn("IsSecureProcess");
		ImGui::TableSetupColumn("IsSubsystemProcess");
		ImGui::TableSetupColumn("HasVisibleWindow");
		ImGui::TableHeadersRow();

		if (g_currentBackend == Backend::Win32)
		{
			for (const auto& proc : g_procListW32)
				DrawProcessRow(proc);
		}
		else
		{
			for (const auto& proc : g_procListNt)
				DrawProcessRow(proc);
		}

		ImGui::EndTable();
	}

	void DrawThreadsTable()
	{

	}

	void DrawModulesTable()
	{

	}

	void DrawHandlesTable()
	{

	}
}