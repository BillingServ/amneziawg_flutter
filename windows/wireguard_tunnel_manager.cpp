#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "wireguard_tunnel_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace amnezia_flutter {

WireGuardTunnelManager::WireGuardTunnelManager() {
    std::cout << "WireGuardTunnelManager: Initializing..." << std::endl;
}

WireGuardTunnelManager::~WireGuardTunnelManager() {
    std::cout << "WireGuardTunnelManager: Cleaning up..." << std::endl;
    stopTunnel();
}

void WireGuardTunnelManager::setEventSink(flutter::EventSink<flutter::EncodableValue>* sink) {
    eventSink = sink;
}

std::wstring WireGuardTunnelManager::getAppDirectory() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    return path.substr(0, path.find_last_of(L"\\/"));
}

std::wstring WireGuardTunnelManager::getAppExecutablePath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    return std::wstring(exePath);
}

bool WireGuardTunnelManager::createConfigFile(const std::string& config) {
    std::wcout << L"WireGuardTunnelManager: Creating config file..." << std::endl;
    
    try {
        // Create a temporary file path
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        // Generate a unique filename based on timestamp
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        
        std::wostringstream pathStream;
        pathStream << tempPath << L"awg_flutter_" << timestamp << L".conf";
        currentConfigPath = pathStream.str();
        
        // Write config to file
        std::ofstream configFile(currentConfigPath);
        if (!configFile.is_open()) {
            std::cerr << "Failed to create config file" << std::endl;
            return false;
        }
        
        configFile << config;
        configFile.close();
        
        std::wcout << L"Config file created: " << currentConfigPath << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception creating config file: " << e.what() << std::endl;
        return false;
    }
}

void WireGuardTunnelManager::cleanupTempFiles() {
    if (!currentConfigPath.empty()) {
        std::wcout << L"WireGuardTunnelManager: Cleaning up config file: " << currentConfigPath << std::endl;
        DeleteFileW(currentConfigPath.c_str());
        currentConfigPath.clear();
    }
}

bool WireGuardTunnelManager::installService() {
    std::cout << "WireGuardTunnelManager: Installing Windows Service..." << std::endl;
    
    // Generate unique service name based on timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::wostringstream serviceNameStream;
    serviceNameStream << L"AmneziaWGTunnel$FlutterVPN_" << timestamp;
    serviceName = serviceNameStream.str();
    
    // Open Service Control Manager
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
        std::cerr << "Ensure application is running as Administrator" << std::endl;
        return false;
    }
    
    // Build command line: "C:\path\to\app.exe" /service "<tunnel_name>" "C:\path\to\config.conf"
    std::wstring exePath = getAppExecutablePath();
    std::wostringstream cmdStream;
    cmdStream << L"\"" << exePath << L"\" /service \"" << serviceName << L"\" \"" << currentConfigPath << L"\"";
    std::wstring cmdLine = cmdStream.str();
    
    std::wcout << L"Service command: " << cmdLine << std::endl;
    
    // Create the service
    serviceHandle = CreateServiceW(
        scm,                                    // SCM database
        serviceName.c_str(),                    // Name of service
        L"AmneziaWG Flutter VPN Tunnel",      // Display name
        SERVICE_ALL_ACCESS,                     // Desired access
        SERVICE_WIN32_OWN_PROCESS,             // Service type
        SERVICE_DEMAND_START,                   // Start type
        SERVICE_ERROR_NORMAL,                   // Error control type
        cmdLine.c_str(),                        // Path to service's binary
        NULL,                                   // No load ordering group
        NULL,                                   // No tag identifier
        L"Nsi\0TcpIp\0",                       // Dependencies
        NULL,                                   // LocalSystem account
        NULL                                    // No password
    );
    
    if (!serviceHandle) {
        DWORD error = GetLastError();
        std::cerr << "Failed to create service. Error: " << error << std::endl;
        CloseServiceHandle(scm);
        return false;
    }
    
    // Set service SID type to UNRESTRICTED (CRITICAL for WireGuard)
    SERVICE_SID_INFO sidInfo;
    sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    
    if (!ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo)) {
        std::cerr << "Warning: Failed to set service SID type. Error: " << GetLastError() << std::endl;
    }
    
    CloseServiceHandle(scm);
    std::cout << "Service installed successfully" << std::endl;
    return true;
}

bool WireGuardTunnelManager::startService() {
    std::cout << "WireGuardTunnelManager: Starting service..." << std::endl;
    
    if (!serviceHandle) {
        std::cerr << "Service handle is NULL" << std::endl;
        return false;
    }
    
    if (!StartServiceW(serviceHandle, 0, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "Failed to start service. Error: " << error << std::endl;
            return false;
        }
    }
    
    std::cout << "Service started successfully" << std::endl;
    return true;
}

bool WireGuardTunnelManager::stopService() {
    std::cout << "WireGuardTunnelManager: Stopping service..." << std::endl;
    
    if (!serviceHandle) {
        return true;
    }
    
    SERVICE_STATUS status;
    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            std::cerr << "Failed to stop service. Error: " << error << std::endl;
        }
    }
    
    // Wait for service to stop
    for (int i = 0; i < 30; i++) {
        if (QueryServiceStatus(serviceHandle, &status)) {
            if (status.dwCurrentState == SERVICE_STOPPED) {
                std::cout << "Service stopped successfully" << std::endl;
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "Service stop timeout" << std::endl;
    return false;
}

bool WireGuardTunnelManager::deleteService() {
    std::cout << "WireGuardTunnelManager: Deleting service..." << std::endl;
    
    if (!serviceHandle) {
        return true;
    }
    
    if (!DeleteService(serviceHandle)) {
        DWORD error = GetLastError();
        std::cerr << "Failed to delete service. Error: " << error << std::endl;
    }
    
    CloseServiceHandle(serviceHandle);
    serviceHandle = nullptr;
    
    std::cout << "Service deleted successfully" << std::endl;
    return true;
}

bool WireGuardTunnelManager::checkConnectionStatus() {
    // Check if WireGuard adapter exists and is up
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    
    if (!addresses) {
        return false;
    }
    
    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
        NULL,
        addresses,
        &bufferSize
    );
    
    bool connected = false;
    
    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES currentAddress = addresses;
        
        while (currentAddress) {
            std::wstring description(currentAddress->Description);
            std::wstring friendlyName(currentAddress->FriendlyName);
            
            // Check if this is an AmneziaWG/WireGuard adapter.
            if (description.find(L"Amnezia") != std::wstring::npos ||
                friendlyName.find(L"Amnezia") != std::wstring::npos ||
                description.find(L"WireGuard") != std::wstring::npos ||
                friendlyName.find(L"WireGuard") != std::wstring::npos) {
                
                // Store the interface name for statistics
                wireguardInterfaceName = friendlyName;
                
                // Check if adapter is up
                if (currentAddress->OperStatus == IfOperStatusUp) {
                    connected = true;
                    break;
                }
            }
            
            currentAddress = currentAddress->Next;
        }
    }
    
    free(addresses);
    return connected;
}

std::map<std::string, uint64_t> WireGuardTunnelManager::getWireGuardInterfaceStatistics() {
    std::map<std::string, uint64_t> stats;
    stats["byte_in"] = 0;
    stats["byte_out"] = 0;
    stats["speed_in_bps"] = 0;
    stats["speed_out_bps"] = 0;
    
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    
    if (!addresses) {
        return stats;
    }
    
    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
        NULL,
        addresses,
        &bufferSize
    );
    
    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES currentAddress = addresses;
        
        while (currentAddress) {
            std::wstring description(currentAddress->Description);
            std::wstring friendlyName(currentAddress->FriendlyName);
            
            // Check if this is an AmneziaWG/WireGuard adapter.
            if (description.find(L"Amnezia") != std::wstring::npos ||
                friendlyName.find(L"Amnezia") != std::wstring::npos ||
                description.find(L"WireGuard") != std::wstring::npos ||
                friendlyName.find(L"WireGuard") != std::wstring::npos) {
                
                // Get statistics from MIB_IF_ROW2
                MIB_IF_ROW2 ifRow;
                ZeroMemory(&ifRow, sizeof(ifRow));
                ifRow.InterfaceLuid = currentAddress->Luid;
                
                if (GetIfEntry2(&ifRow) == NO_ERROR) {
                    uint64_t currentBytesIn = ifRow.InOctets;
                    uint64_t currentBytesOut = ifRow.OutOctets;
                    
                    stats["byte_in"] = currentBytesIn;
                    stats["byte_out"] = currentBytesOut;
                    
                    // Calculate instantaneous speeds (raw, no smoothing)
                    // Smoothing will be handled in Dart layer for flexibility
                    auto now = std::chrono::system_clock::now();
                    
                    // Initialize on first call
                    if (lastStatsTime.time_since_epoch().count() == 0) {
                        lastBytesIn = currentBytesIn;
                        lastBytesOut = currentBytesOut;
                        lastStatsTime = now;
                        stats["speed_in_bps"] = 0;
                        stats["speed_out_bps"] = 0;
                    } else {
                        // Calculate time difference
                        auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastStatsTime);
                        double timeDiffSeconds = timeDiff.count() / 1000.0;
                        
                        // Only calculate if we have at least 100ms elapsed
                        if (timeDiffSeconds >= 0.1) {
                            // Calculate byte differences
                            uint64_t byteInDiff = (currentBytesIn > lastBytesIn) ? (currentBytesIn - lastBytesIn) : 0;
                            uint64_t byteOutDiff = (currentBytesOut > lastBytesOut) ? (currentBytesOut - lastBytesOut) : 0;
                            
                            // Calculate RAW instantaneous speeds (bytes per second)
                            // No smoothing here - Dart will handle that
                            double rawSpeedIn = byteInDiff / timeDiffSeconds;
                            double rawSpeedOut = byteOutDiff / timeDiffSeconds;
                            
                            stats["speed_in_bps"] = static_cast<uint64_t>(rawSpeedIn);
                            stats["speed_out_bps"] = static_cast<uint64_t>(rawSpeedOut);
                            
                            // Update tracking variables
                            lastBytesIn = currentBytesIn;
                            lastBytesOut = currentBytesOut;
                            lastStatsTime = now;
                        }
                    }
                }
                break;
            }
            
            currentAddress = currentAddress->Next;
        }
    }
    
    free(addresses);
    return stats;
}

std::map<std::string, uint64_t> WireGuardTunnelManager::getStatistics() {
    if (!isConnected) {
        // Reset tracking on disconnect
        lastBytesIn = 0;
        lastBytesOut = 0;
        lastStatsTime = std::chrono::system_clock::time_point{};
        return {{"byte_in", 0}, {"byte_out", 0}, {"speed_in_bps", 0}, {"speed_out_bps", 0}};
    }
    
    return getWireGuardInterfaceStatistics();
}

void WireGuardTunnelManager::monitorConnection() {
    std::cout << "WireGuardTunnelManager: Starting connection monitor..." << std::endl;
    
    int connectionCheckAttempts = 0;
    const int maxConnectionCheckAttempts = 30; // 30 seconds
    
    while (shouldMonitor) {
        // Check for actual connection
        if (isConnecting && checkConnectionStatus()) {
            std::cout << "WireGuard connection established!" << std::endl;
            isConnecting = false;
            isConnected = true;
            updateStatusThreadSafe("connected");
        } else if (isConnecting) {
            connectionCheckAttempts++;
            if (connectionCheckAttempts >= maxConnectionCheckAttempts) {
                std::cerr << "Connection timeout - adapter not coming up" << std::endl;
                updateStatusThreadSafe("error");
                break;
            }
        }
        
        // Check if connected adapter went down
        if (isConnected && !checkConnectionStatus()) {
            std::cout << "WireGuard connection lost" << std::endl;
            isConnected = false;
            updateStatusThreadSafe("disconnected");
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "Connection monitor stopped" << std::endl;
}

bool WireGuardTunnelManager::startTunnel(const std::string& config) {
    std::lock_guard<std::mutex> lock(statusMutex);
    
    if (isConnected || isConnecting) {
        std::cerr << "WireGuardTunnelManager: Already connected or connecting" << std::endl;
        return false;
    }
    
    std::cout << "WireGuardTunnelManager: Starting tunnel..." << std::endl;
    
    // Create config file
    if (!createConfigFile(config)) {
        return false;
    }
    
    // Install Windows Service
    if (!installService()) {
        cleanupTempFiles();
        return false;
    }
    
    // Start the service
    if (!startService()) {
        deleteService();
        cleanupTempFiles();
        return false;
    }
    
    // Reset flags and statistics
    isConnecting = true;
    connectionStartTime = std::chrono::system_clock::now();
    
    // Reset speed tracking for new connection
    lastBytesIn = 0;
    lastBytesOut = 0;
    lastStatsTime = std::chrono::system_clock::time_point{};
    
    updateStatus("connecting");
    
    // Start monitoring thread
    shouldMonitor = true;
    statusMonitorThread = std::thread(&WireGuardTunnelManager::monitorConnection, this);
    
    std::cout << "WireGuardTunnelManager: Tunnel start initiated" << std::endl;
    return true;
}

void WireGuardTunnelManager::stopTunnel() {
    std::cout << "WireGuardTunnelManager: Stopping tunnel..." << std::endl;
    
    // Signal monitor to stop
    shouldMonitor = false;
    
    // Wait for monitoring thread
    if (statusMonitorThread.joinable()) {
        statusMonitorThread.join();
    }
    
    // Stop and delete the service
    stopService();
    deleteService();
    
    isConnected = false;
    isConnecting = false;
    
    std::lock_guard<std::mutex> lock(statusMutex);
    updateStatus("disconnected");
    
    // Cleanup
    cleanupTempFiles();
    
    std::cout << "WireGuardTunnelManager: Tunnel stopped" << std::endl;
}

std::string WireGuardTunnelManager::getStatus() {
    std::lock_guard<std::mutex> lock(statusMutex);
    return currentStatus;
}

void WireGuardTunnelManager::updateStatus(const std::string& status) {
    currentStatus = status;
    if (eventSink) {
        eventSink->Success(flutter::EncodableValue(status));
    }
    std::cout << "WireGuardTunnelManager: Status updated to: " << status << std::endl;
}

void WireGuardTunnelManager::updateStatusThreadSafe(const std::string& status) {
    std::lock_guard<std::mutex> lock(statusMutex);
    pendingStatusUpdates.push(status);
}

void WireGuardTunnelManager::processPendingStatusUpdates() {
    std::lock_guard<std::mutex> lock(statusMutex);
    while (!pendingStatusUpdates.empty()) {
        updateStatus(pendingStatusUpdates.front());
        pendingStatusUpdates.pop();
    }
}

} // namespace amnezia_flutter
