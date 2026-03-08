#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include "flutter_window.h"
#include "utils.h"

namespace {

std::wstring Utf8ToWide(const std::string& input) {
  if (input.empty()) {
    return std::wstring();
  }
  const int length = ::MultiByteToWideChar(
      CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
  std::wstring output(length, L'\0');
  ::MultiByteToWideChar(
      CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), length);
  return output;
}

std::wstring GetModuleDirectory() {
  wchar_t module_path[MAX_PATH];
  ::GetModuleFileNameW(nullptr, module_path, MAX_PATH);
  std::wstring path(module_path);
  return path.substr(0, path.find_last_of(L"\\/"));
}

bool ReadUtf8File(const std::wstring& path, std::wstring* contents) {
  FILE* file = nullptr;
  if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr) {
    return false;
  }

  std::ostringstream buffer;
  char chunk[4096];
  size_t read = 0;
  while ((read = std::fread(chunk, 1, sizeof(chunk), file)) > 0) {
    buffer.write(chunk, static_cast<std::streamsize>(read));
  }
  std::fclose(file);
  *contents = Utf8ToWide(buffer.str());
  return true;
}

int RunTunnelService(const std::vector<std::string>& args) {
  if (args.size() < 3) {
    return EXIT_FAILURE;
  }

  const std::wstring tunnel_name = Utf8ToWide(args[1]);
  const std::wstring config_path = Utf8ToWide(args[2]);

  std::wstring config_contents;
  if (!ReadUtf8File(config_path, &config_contents)) {
    return EXIT_FAILURE;
  }

  const std::wstring tunnel_dll_path = GetModuleDirectory() + L"\\tunnel.dll";
  HMODULE tunnel_dll = ::LoadLibraryW(tunnel_dll_path.c_str());
  if (tunnel_dll == nullptr) {
    return EXIT_FAILURE;
  }

  using WireGuardTunnelServiceFn = unsigned char (*)(unsigned short*, unsigned short*);
  const auto service_fn = reinterpret_cast<WireGuardTunnelServiceFn>(
      ::GetProcAddress(tunnel_dll, "WireGuardTunnelService"));
  if (service_fn == nullptr) {
    ::FreeLibrary(tunnel_dll);
    return EXIT_FAILURE;
  }

  std::vector<unsigned short> config_utf16(config_contents.begin(), config_contents.end());
  std::vector<unsigned short> name_utf16(tunnel_name.begin(), tunnel_name.end());
  config_utf16.push_back(0);
  name_utf16.push_back(0);

  const bool ok = service_fn(config_utf16.data(), name_utf16.data()) != 0;
  ::FreeLibrary(tunnel_dll);
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  if (!command_line_arguments.empty() &&
      command_line_arguments[0] == "/service") {
    return RunTunnelService(command_line_arguments);
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");
  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);
  if (!window.CreateAndShow(L"wireguard_dart_example", origin, size)) {
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
