#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <map>
#include <flutter/event_channel.h>
#include <flutter/encodable_value.h>

namespace wireguard_flutter {

class WireGuardTunnelManager {
private:
    // Service handle
    SC_HANDLE serviceHandle = nullptr;
    std::wstring serviceName;
    
    // Connection state
    std::atomic<bool> isConnected{false};
    std::atomic<bool> isConnecting{false};
    std::string currentStatus = "disconnected";
    std::wstring currentConfigPath;
    
    // Status monitoring
    std::thread statusMonitorThread;
    std::atomic<bool> shouldMonitor{true};
    
    // Event sink for status updates
    flutter::EventSink<flutter::EncodableValue>* eventSink = nullptr;
    
    // Thread safety
    std::mutex statusMutex;
    std::queue<std::string> pendingStatusUpdates;
    
    // Connection tracking
    std::chrono::system_clock::time_point connectionStartTime;
    
    // WireGuard interface name for stats
    std::wstring wireguardInterfaceName;
    
    // Speed tracking (for calculating instantaneous speeds)
    uint64_t lastBytesIn = 0;
    uint64_t lastBytesOut = 0;
    std::chrono::system_clock::time_point lastStatsTime;

public:
    WireGuardTunnelManager();
    ~WireGuardTunnelManager();
    
    void setEventSink(flutter::EventSink<flutter::EncodableValue>* sink);
    bool startTunnel(const std::string& config);
    void stopTunnel();
    std::string getStatus();
    std::map<std::string, uint64_t> getStatistics();
    
    // Process pending status updates (call from main thread)
    void processPendingStatusUpdates();
    
private:
    bool installService();
    bool startService();
    bool stopService();
    bool deleteService();
    void monitorConnection();
    void updateStatus(const std::string& status);
    void updateStatusThreadSafe(const std::string& status);
    bool createConfigFile(const std::string& config);
    void cleanupTempFiles();
    bool checkConnectionStatus();
    std::wstring getAppDirectory();
    std::wstring getAppExecutablePath();
    std::map<std::string, uint64_t> getWireGuardInterfaceStatistics();
};

} // namespace wireguard_flutter
