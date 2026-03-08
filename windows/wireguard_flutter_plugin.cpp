#include "wireguard_flutter_plugin.h"

// This must be included before many other Windows headers.
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/encodable_value.h>
#include <libbase64.h>
#include <windows.h>

#include <memory>
#include <sstream>

#include "wireguard_tunnel_manager.h"
#include "utils.h"

using namespace flutter;
using namespace std;

namespace wireguard_flutter
{

  // static
  void WireguardFlutterPlugin::RegisterWithRegistrar(PluginRegistrarWindows *registrar)
  {
    auto channel = make_unique<MethodChannel<EncodableValue>>(
        registrar->messenger(), "billion.group.wireguard_flutter/wgcontrol", &StandardMethodCodec::GetInstance());
    auto eventChannel = make_unique<EventChannel<EncodableValue>>(
        registrar->messenger(), "billion.group.wireguard_flutter/wgstage", &StandardMethodCodec::GetInstance());

    auto plugin = make_unique<WireguardFlutterPlugin>();

    channel->SetMethodCallHandler([plugin_pointer = plugin.get()](const auto &call, auto result)
                                  { plugin_pointer->HandleMethodCall(call, move(result)); });

    auto eventsHandler = make_unique<StreamHandlerFunctions<EncodableValue>>(
        [plugin_pointer = plugin.get()](
            const EncodableValue *arguments,
            unique_ptr<EventSink<EncodableValue>> &&events)
            -> unique_ptr<StreamHandlerError<EncodableValue>>
        {
          return plugin_pointer->OnListen(arguments, move(events));
        },
        [plugin_pointer = plugin.get()](const EncodableValue *arguments)
            -> unique_ptr<StreamHandlerError<EncodableValue>>
        {
          return plugin_pointer->OnCancel(arguments);
        });

    eventChannel->SetStreamHandler(move(eventsHandler));

    registrar->AddPlugin(move(plugin));
  }

  WireguardFlutterPlugin::WireguardFlutterPlugin() {
    // Create tunnel manager
    tunnel_manager_ = make_unique<WireGuardTunnelManager>();
    cout << "WireguardFlutterPlugin: Created with embedded tunnel manager" << endl;
  }

  WireguardFlutterPlugin::~WireguardFlutterPlugin() {}

  void WireguardFlutterPlugin::HandleMethodCall(const MethodCall<EncodableValue> &call,
                                                unique_ptr<MethodResult<EncodableValue>> result)
  {
    const auto *args = get_if<EncodableMap>(call.arguments());

    if (call.method_name() == "initialize")
    {
      // For the embedded approach, we don't need win32ServiceName
      // Just acknowledge initialization
      cout << "WireguardFlutterPlugin: Initialize called (embedded mode)" << endl;
      
      if (tunnel_manager_ && events_) {
        tunnel_manager_->setEventSink(events_.get());
      }
      
      result->Success();
      return;
    }
    else if (call.method_name() == "start")
    {
      if (tunnel_manager_ == nullptr)
      {
        result->Error("Invalid state: tunnel manager not initialized");
        return;
      }
      
      const auto *wgQuickConfig = get_if<string>(ValueOrNull(*args, "wgQuickConfig"));
      if (wgQuickConfig == NULL)
      {
        result->Error("Argument 'wgQuickConfig' is required");
        return;
      }

      cout << "WireguardFlutterPlugin: Starting tunnel with embedded approach" << endl;
      
      try
      {
        bool success = tunnel_manager_->startTunnel(*wgQuickConfig);
        if (success) {
          result->Success();
        } else {
          result->Error("Failed to start tunnel");
        }
      }
      catch (exception &e)
      {
        result->Error(string("Tunnel start error: ").append(e.what()));
      }
      return;
    }
    else if (call.method_name() == "stop")
    {
      if (tunnel_manager_ == nullptr)
      {
        result->Error("Invalid state: tunnel manager not initialized");
        return;
      }

      cout << "WireguardFlutterPlugin: Stopping tunnel" << endl;
      
      try
      {
        tunnel_manager_->stopTunnel();
        result->Success();
      }
      catch (exception &e)
      {
        result->Error(string(e.what()));
      }
      return;
    }
    else if (call.method_name() == "stage")
    {
      if (tunnel_manager_ == nullptr)
      {
        result->Error("Invalid state: tunnel manager not initialized");
        return;
      }

      string status = tunnel_manager_->getStatus();
      result->Success(status);
      return;
    }
    else if (call.method_name() == "getWireGuardStatistics")
    {
      if (tunnel_manager_ == nullptr)
      {
        result->Error("Invalid state: tunnel manager not initialized");
        return;
      }

      try
      {
        auto stats = tunnel_manager_->getStatistics();
        
        EncodableMap statsMap;
        statsMap[EncodableValue("byte_in")] = EncodableValue(static_cast<int64_t>(stats["byte_in"]));
        statsMap[EncodableValue("byte_out")] = EncodableValue(static_cast<int64_t>(stats["byte_out"]));
        statsMap[EncodableValue("speed_in_bps")] = EncodableValue(static_cast<int64_t>(stats["speed_in_bps"]));
        statsMap[EncodableValue("speed_out_bps")] = EncodableValue(static_cast<int64_t>(stats["speed_out_bps"]));
        
        result->Success(EncodableValue(statsMap));
      }
      catch (exception &e)
      {
        result->Error(string("Statistics error: ").append(e.what()));
      }
      return;
    }

    result->NotImplemented();
  }

  unique_ptr<StreamHandlerError<EncodableValue>> WireguardFlutterPlugin::OnListen(
      const EncodableValue *arguments,
      unique_ptr<EventSink<EncodableValue>> &&events)
  {
    events_ = move(events);
    if (tunnel_manager_ != nullptr)
    {
      tunnel_manager_->setEventSink(events_.get());
    }
    return nullptr;
  }

  unique_ptr<StreamHandlerError<EncodableValue>> WireguardFlutterPlugin::OnCancel(
      const EncodableValue *arguments)
  {
    events_ = nullptr;
    if (tunnel_manager_ != nullptr)
    {
      tunnel_manager_->setEventSink(nullptr);
    }
    return nullptr;
  }

} // namespace wireguard_flutter
