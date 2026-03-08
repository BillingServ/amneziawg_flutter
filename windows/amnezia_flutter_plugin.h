#ifndef FLUTTER_PLUGIN_AMNEZIA_FLUTTER_PLUGIN_H_
#define FLUTTER_PLUGIN_AMNEZIA_FLUTTER_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/encodable_value.h>

#include <memory>

#include "wireguard_tunnel_manager.h"

namespace amnezia_flutter
{

  class AmneziaFlutterPlugin : public flutter::Plugin
  {
  public:
    static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

    AmneziaFlutterPlugin();

    virtual ~AmneziaFlutterPlugin();

    // Disallow copy and assign.
    AmneziaFlutterPlugin(const AmneziaFlutterPlugin &) = delete;
    AmneziaFlutterPlugin &operator=(const AmneziaFlutterPlugin &) = delete;

  private:
    // Called when a method is called on this plugin's channel from Dart.
    void HandleMethodCall(const flutter::MethodCall<flutter::EncodableValue> &method_call,
                          std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

    std::unique_ptr<WireGuardTunnelManager> tunnel_manager_;
    std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> events_;

    std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> OnListen(
        const flutter::EncodableValue *arguments,
        std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> &&events);
    std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> OnCancel(
        const flutter::EncodableValue *arguments);
  };

} // namespace amnezia_flutter

#endif // FLUTTER_PLUGIN_AMNEZIA_FLUTTER_PLUGIN_H_
