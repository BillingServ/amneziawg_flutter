#include "include/amnezia_flutter/amnezia_flutter_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "amnezia_flutter_plugin.h"

void AmneziaFlutterPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  amnezia_flutter::AmneziaFlutterPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
