#if os(iOS)
import Flutter
import UIKit
#elseif os(macOS)
import FlutterMacOS
import Cocoa
#else
#error("Unsupported platform")
#endif

import NetworkExtension

public class AmneziaFlutterPlugin: NSObject, FlutterPlugin {
    private static var utils : VPNUtils! = VPNUtils()
     
    public static var stage: FlutterEventSink?
    private var initialized : Bool = false
     var wireguardMethodChannel: FlutterMethodChannel?
    
    public static func register(with registrar: FlutterPluginRegistrar) {
       
        let instance = AmneziaFlutterPlugin()
        instance.onRegister(registrar)
    }
    
    public func onRegister(_ registrar: FlutterPluginRegistrar){
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif
        let wireguardMethodChannel = FlutterMethodChannel(name: "billion.group.amnezia_flutter/wgcontrol", binaryMessenger: messenger)
        let vpnStageE = FlutterEventChannel(
      name: "billion.group.amnezia_flutter/wgstage", binaryMessenger: messenger)
        vpnStageE.setStreamHandler(VPNConnectionHandler())
        wireguardMethodChannel.setMethodCallHandler({(call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            switch call.method {
            case "stage":
               if let status = AmneziaFlutterPlugin.utils.currentStatus() {
                   result(status)
               } else {
                   result(FlutterError(code: "VPN_IDENTITY_UNKNOWN",
                       message: "Initialize with providerBundleIdentifier before querying state", details: nil))
               }
                break;
            case "initialize":
              let localizedDescription: String? =
              (call.arguments as? [String: Any])?["localizedDescription"] as? String
              if localizedDescription == nil {
                  result(
                    FlutterError(
                        code: "-3", message: "localizedDescription content empty or null", details: nil))
                  return
              }
              AmneziaFlutterPlugin.utils.localizedDescription = localizedDescription
              if let identifier = (call.arguments as? [String: Any])?["providerBundleIdentifier"] as? String,
                 !identifier.isEmpty {
                  AmneziaFlutterPlugin.utils.providerBundleIdentifier = identifier
              }
              AmneziaFlutterPlugin.utils.loadProviderManager { (err: Error?) in
                  if err == nil {
                      result(AmneziaFlutterPlugin.utils.currentStatus())
                  } else {
                      result(
                        FlutterError(
                            code: "-4", message: err.debugDescription, details: err?.localizedDescription))
                  }
              }
                self.initialized = true
                break;
            case "stop":
                self.disconnect(result: result)
                break;
            case "start":
                 let serverAddress: String? = (call.arguments as? [String: Any])?["serverAddress"] as? String
                 let wgQuickConfig: String? = (call.arguments as? [String: Any])?["wgQuickConfig"] as? String
                 let providerBundleIdentifier: String? = (call.arguments as? [String: Any])?["providerBundleIdentifier"] as? String
                 let onDemand = (call.arguments as? [String: Any])?["onDemand"] as? Bool ?? false
                 let includeAllNetworks = (call.arguments as? [String: Any])?["includeAllNetworks"] as? Bool ?? false
              self.connect(serverAddress: serverAddress!, wgQuickConfig: wgQuickConfig!,providerBundleIdentifier: providerBundleIdentifier!, onDemand: onDemand, includeAllNetworks: includeAllNetworks, result: result)
                break;
            case "dispose":
                self.initialized = false
            default:
                break;
            }
        })
    }
    private func connect(serverAddress: String, wgQuickConfig: String, providerBundleIdentifier:String, onDemand: Bool, includeAllNetworks: Bool, result: @escaping FlutterResult) {
        AmneziaFlutterPlugin.utils.configureVPN(serverAddress: serverAddress, wgQuickConfig: wgQuickConfig, providerBundleIdentifier: providerBundleIdentifier, onDemand: onDemand, includeAllNetworks: includeAllNetworks) { success in
                result(success)
            }
        }
        private func disconnect(result: @escaping FlutterResult) {
            AmneziaFlutterPlugin.utils.stopVPN(){ succes in
                result(succes)
            }
        }
    
    class VPNConnectionHandler: NSObject, FlutterStreamHandler {
    private var vpnConnection: FlutterEventSink?
    private var vpnConnectionObserver: NSObjectProtocol?

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
      -> FlutterError?
    {
      // Remove existing observer if any
      if let observer = vpnConnectionObserver {
        NotificationCenter.default.removeObserver(observer)
      }

      vpnConnectionObserver = NotificationCenter.default.addObserver(
        forName: NSNotification.Name.NEVPNStatusDidChange, object: nil, queue: .main
      ) { [weak self] notification in
        guard let self = self, let connection = self.vpnConnection else {
          // Check if self or connection is nil and return early if that's the case
          return
        }

        guard let nevpnconn = notification.object as? NEVPNConnection,
              AmneziaFlutterPlugin.utils.ownsConnection(nevpnconn) else { return }
        let status = nevpnconn.status

        // Send the event using the eventSink closure
        connection(AmneziaFlutterPlugin.utils.onVpnStatusChangedString(notification: status))
      }

      // Assign the eventSink closure to the vpnConnection variable
      self.vpnConnection = events

      if let status = AmneziaFlutterPlugin.utils.currentStatus() {
          events(status)
      } else {
          events(FlutterError(code: "VPN_IDENTITY_UNKNOWN",
              message: "VPN provider identity is not initialized", details: nil))
      }

      return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
      if let observer = vpnConnectionObserver {
        NotificationCenter.default.removeObserver(observer)
      }
      vpnConnection = nil

      return nil
    }
  }
    
    
}


@available(iOS 15.0, *)
class VPNUtils {
  private var operationGeneration: UInt64 = 0
  private var pendingStart: ((Bool) -> Void)?
  var providerManager: NETunnelProviderManager!
  var providerBundleIdentifier: String? {
    didSet {
      guard oldValue != providerBundleIdentifier else { return }
      operationGeneration &+= 1
      providerManager = nil
      let cancelledStart = pendingStart
      pendingStart = nil
      cancelledStart?(false)
    }
  }
  var localizedDescription: String?
  var groupIdentifier: String?
  var serverAddress: String?
  var stage: FlutterEventSink!
   
  func ownsManager(_ manager: NETunnelProviderManager) -> Bool {
    guard let identifier = providerBundleIdentifier, !identifier.isEmpty,
          let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
    return configuration.providerBundleIdentifier == identifier
  }

  func ownsConnection(_ connection: NEVPNConnection) -> Bool {
    guard let manager = providerManager, ownsManager(manager) else { return false }
    return connection === manager.connection
  }

  func loadProviderManager(completion: @escaping (_ error: Error?) -> Void) {
    let generation = operationGeneration
    NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
      guard self.operationGeneration == generation else { completion(nil); return }
      if error == nil {
        self.providerManager = managers?.first(where: self.ownsManager)
        completion(nil)
      } else {
        completion(error)
      }
    }
  }

  func onVpnStatusChanged(notification: NEVPNStatus) {
    switch notification {
    case .connected:
      stage?("connected")
      break
    case .connecting:
      stage?("connecting")
      break
    case .disconnected:
      stage?("disconnected")
      break
    case .disconnecting:
      stage?("disconnecting")
      break
    case .invalid:
        stage?("invalid")
        break
    case .reasserting:
        stage?("reasserting")
        break
    @unknown default:
        stage?("disconnected")
        break
    }
  }

  func onVpnStatusChangedString(notification: NEVPNStatus?) -> String? {
    if notification == nil {
      return "disconnected"
    }
    switch notification! {
    case NEVPNStatus.connected:
      return "connected"
    case NEVPNStatus.connecting:
      return "connecting"
    case NEVPNStatus.disconnected:
      return "disconnected"
    case NEVPNStatus.disconnecting:
      return "disconnecting"
    case NEVPNStatus.invalid:
      return "invalid"
    case NEVPNStatus.reasserting:
      return "reasserting"
    default:
      return ""
    }
  }

  func currentStatus() -> String? {
    guard let identifier = providerBundleIdentifier, !identifier.isEmpty else { return nil }
    if let manager = self.providerManager, ownsManager(manager) {
      return onVpnStatusChangedString(notification: manager.connection.status)
    } else {
      return "disconnected"
    }
    //        return "DISCONNECTED"
  }
   
    func configureVPN(
        serverAddress: String?,
        wgQuickConfig: String?,
        providerBundleIdentifier: String?,
        onDemand: Bool = false,
        includeAllNetworks: Bool = false,
        completion: @escaping (Bool) -> Void
      ) {
          guard let providerBundleIdentifier = providerBundleIdentifier,
                !providerBundleIdentifier.isEmpty else { completion(false); return }
          self.providerBundleIdentifier = providerBundleIdentifier
          operationGeneration &+= 1
          let generation = operationGeneration
          let previousStart = pendingStart
          pendingStart = completion
          previousStart?(false)
          let complete: (Bool) -> Void = { [weak self] success in
              guard let self = self, self.operationGeneration == generation else { return }
              let callback = self.pendingStart
              self.pendingStart = nil
              callback?(success)
          }
          NETunnelProviderManager.loadAllFromPreferences{ tunnelManagersInSettings, error in
              guard self.operationGeneration == generation else { return }
              if let error = error {
                  NSLog("Error (loadAllFromPreferences): \(error)")
                  complete(false)
                  return
              }
              let preExistingTunnelManager = tunnelManagersInSettings?.first(where: self.ownsManager)
              let tunnelManager = preExistingTunnelManager ?? NETunnelProviderManager()
              self.providerManager = tunnelManager
              
              let protocolConfiguration = NETunnelProviderProtocol()
              
              protocolConfiguration.providerBundleIdentifier = providerBundleIdentifier
              protocolConfiguration.serverAddress = serverAddress
              protocolConfiguration.providerConfiguration = [
                  "WgQuickConfig": wgQuickConfig!,
                  "wgQuickConfig": wgQuickConfig!
              ]
              
              // All traffic but the local network's goes through the tunnel, and
              // is blocked whenever the tunnel isn't passing it.
              protocolConfiguration.includeAllNetworks = includeAllNetworks
              protocolConfiguration.excludeLocalNetworks = includeAllNetworks

              tunnelManager.protocolConfiguration = protocolConfiguration
              tunnelManager.isEnabled = true
              // Keeps the tunnel up: the system restarts it whenever it drops.
              let connectRule = NEOnDemandRuleConnect()
              connectRule.interfaceTypeMatch = .any
              tunnelManager.onDemandRules = onDemand ? [connectRule] : nil
              tunnelManager.isOnDemandEnabled = onDemand
              
              tunnelManager.saveToPreferences { error in
                  guard self.operationGeneration == generation else { return }
                  if let error = error {
                      NSLog("Error (saveToPreferences): \(error)")
                      complete(false)
                  } else {
                      tunnelManager.loadFromPreferences { error in
                          guard self.operationGeneration == generation else { return }
                          if let error = error {
                              NSLog("Error (loadFromPreferences): \(error)")
                              complete(false)
                          } else {
                              NSLog("Starting the tunnel")
                              if let session = tunnelManager.connection as? NETunnelProviderSession {
                                  do {
                                      try session.startTunnel(options: nil)
                                      complete(true)
                                  } catch {
                                      NSLog("Error (startTunnel): \(error)")
                                      complete(false)
                                  }
                              } else {
                                  NSLog("tunnelManager.connection is invalid")
                                  complete(false)
                              }
                          }
                      }
                  }
              }
          }
         
      }
  
  func stopVPN(completion: @escaping (Bool?) -> Void) {
      operationGeneration &+= 1
      let generation = operationGeneration
      let cancelledStart = pendingStart
      pendingStart = nil
      cancelledStart?(false)
      NETunnelProviderManager.loadAllFromPreferences { tunnelManagersInSettings, error in
          guard self.operationGeneration == generation else {
              completion(false)
              return
          }
          if let error = error {
              NSLog("Error (loadAllFromPreferences): \(error)")
              completion(false)
              return
          }
          
          if let tunnelManager = tunnelManagersInSettings?.first(where: self.ownsManager) {
              guard let session = tunnelManager.connection as? NETunnelProviderSession else {
                  NSLog("tunnelManager.connection is invalid")
                  completion(false)
                  return
              }
              let stop = {
                  switch session.status {
                  case .connected, .connecting, .reasserting:
                      NSLog("Stopping the tunnel")
                      session.stopTunnel()
                      completion(true)
                  default:
                      completion(false)
                  }
              }
              // A deliberate stop: with on-demand still on, the system would
              // start the tunnel again straight away, and with all networks
              // included it would keep blocking traffic while it is down.
              let configuration = tunnelManager.protocolConfiguration as? NETunnelProviderProtocol
              if tunnelManager.isOnDemandEnabled || configuration?.includeAllNetworks == true {
                  tunnelManager.isOnDemandEnabled = false
                  configuration?.includeAllNetworks = false
                  configuration?.excludeLocalNetworks = false
                  tunnelManager.saveToPreferences { _ in stop() }
              } else {
                  stop()
              }
          } else {
              completion(false)
          }
      }
  }
   
}
