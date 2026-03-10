#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "wireguard_tunnel_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace amnezia_flutter {

namespace {

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    const int sizeNeeded = WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string output(sizeNeeded, '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), output.data(), sizeNeeded, nullptr, nullptr);
    return output;
}

std::string trimCopy(std::string value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::string operStatusToString(IF_OPER_STATUS status) {
    switch (status) {
        case IfOperStatusUp:
            return "up";
        case IfOperStatusDown:
            return "down";
        case IfOperStatusTesting:
            return "testing";
        case IfOperStatusUnknown:
            return "unknown";
        case IfOperStatusDormant:
            return "dormant";
        case IfOperStatusNotPresent:
            return "not_present";
        case IfOperStatusLowerLayerDown:
            return "lower_layer_down";
        default:
            return "status_" + std::to_string(static_cast<int>(status));
    }
}

std::string wireGuardServiceErrorToString(DWORD code) {
    switch (code) {
        case 0:
            return "success";
        case 1:
            return "ringlogger_open_failed";
        case 2:
            return "load_configuration_failed";
        case 3:
            return "create_network_adapter_failed";
        case 4:
            return "uapi_listen_failed";
        case 5:
            return "dns_lookup_failed";
        case 6:
            return "firewall_enable_failed";
        case 7:
            return "device_set_config_failed";
        case 8:
            return "device_bring_up_failed";
        case 9:
            return "bind_sockets_to_default_route_failed";
        case 10:
            return "monitor_mtu_changes_failed";
        case 11:
            return "set_adapter_network_config_failed";
        case 12:
            return "determine_executable_path_failed";
        case 13:
            return "track_tunnels_failed";
        case 14:
            return "enumerate_sessions_failed";
        case 15:
            return "drop_privileges_failed";
        case 16:
            return "run_script_failed";
        case 17:
            return "internal_win32_error";
        default:
            return "unknown_service_error_" + std::to_string(code);
    }
}

}  // namespace

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
        logConfigSummary(config);
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
    logServiceStatus("after StartServiceW");
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
    PIP_ADAPTER_ADDRESSES addresses = nullptr;
    ULONG result = ERROR_BUFFER_OVERFLOW;

    while (result == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(bufferSize));
        if (!addresses) {
            return false;
        }

        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            NULL,
            addresses,
            &bufferSize
        );
    }
    
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
                std::cout << "WireGuardTunnelManager: Candidate adapter detected"
                          << " name=" << narrow(friendlyName)
                          << " description=" << narrow(description)
                          << " oper_status=" << operStatusToString(currentAddress->OperStatus)
                          << std::endl;
                
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
    PIP_ADAPTER_ADDRESSES addresses = nullptr;
    ULONG result = ERROR_BUFFER_OVERFLOW;

    while (result == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(bufferSize));
        if (!addresses) {
            return stats;
        }

        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            NULL,
            addresses,
            &bufferSize
        );
    }
    
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
            logAdapterSnapshot("connected");
            updateStatusThreadSafe("connected");
        } else if (isConnecting) {
            connectionCheckAttempts++;
            if (connectionCheckAttempts == 1 || connectionCheckAttempts % 5 == 0) {
                std::cout << "WireGuardTunnelManager: Connection poll attempt "
                          << connectionCheckAttempts << "/" << maxConnectionCheckAttempts << std::endl;
                logServiceStatus("connection poll");
                logAdapterSnapshot("connection poll");
            }
            if (connectionCheckAttempts >= maxConnectionCheckAttempts) {
                std::cerr << "Connection timeout - adapter not coming up" << std::endl;
                logServiceStatus("timeout");
                logAdapterSnapshot("timeout");
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
    logRuntimeDependencies();
    
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
    currentStatus = status;
    pendingStatusUpdates.push(status);
}

void WireGuardTunnelManager::processPendingStatusUpdates() {
    std::lock_guard<std::mutex> lock(statusMutex);
    while (!pendingStatusUpdates.empty()) {
        updateStatus(pendingStatusUpdates.front());
        pendingStatusUpdates.pop();
    }
}

void WireGuardTunnelManager::logConfigSummary(const std::string& config) {
    std::istringstream stream(config);
    std::string line;
    std::string endpoint;
    std::string address;
    std::string allowedIps;
    std::string publicKey;

    while (std::getline(stream, line)) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }

        const std::string key = trimCopy(line.substr(0, separator));
        const std::string value = trimCopy(line.substr(separator + 1));
        if (key == "Endpoint") {
            endpoint = value;
        } else if (key == "Address") {
            address = value;
        } else if (key == "AllowedIPs") {
            allowedIps = value;
        } else if (key == "PublicKey") {
            publicKey = value;
        }
    }

    std::cout << "WireGuardTunnelManager: Config summary"
              << " endpoint=" << (endpoint.empty() ? "<missing>" : endpoint)
              << " address=" << (address.empty() ? "<missing>" : address)
              << " allowed_ips=" << (allowedIps.empty() ? "<missing>" : allowedIps)
              << " peer_key_prefix="
              << (publicKey.empty() ? "<missing>" : publicKey.substr(0, std::min<size_t>(8, publicKey.size())))
              << std::endl;
}

void WireGuardTunnelManager::logRuntimeDependencies() {
    const std::wstring appDir = getAppDirectory();
    const std::wstring amneziaPreferredTunnelPath = appDir + L"\\amneziawg_tunnel.dll";
    const std::wstring amneziaTunnelPath = appDir + L"\\amnezia_tunnel.dll";
    const std::wstring wireGuardTunnelPath = appDir + L"\\wireguard_tunnel.dll";
    const std::wstring fallbackTunnelPath = appDir + L"\\tunnel.dll";
    const std::wstring wintunPath = appDir + L"\\wintun.dll";
    const std::wstring wireguardDriverPath = appDir + L"\\wireguard.dll";
    const std::wstring awgPath = appDir + L"\\awg.exe";

    auto logFileStatus = [&](const std::wstring& path, const std::string& label) {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        const bool exists = attributes != INVALID_FILE_ATTRIBUTES &&
                            !(attributes & FILE_ATTRIBUTE_DIRECTORY);
        std::cout << "WireGuardTunnelManager: Dependency check"
                  << " label=" << label
                  << " exists=" << (exists ? "yes" : "no")
                  << " path=" << narrow(path)
                  << std::endl;
    };

    std::cout << "WireGuardTunnelManager: App directory -> " << narrow(appDir) << std::endl;
    logFileStatus(amneziaPreferredTunnelPath, "amneziawg_tunnel.dll");
    logFileStatus(amneziaTunnelPath, "amnezia_tunnel.dll");
    logFileStatus(wireGuardTunnelPath, "wireguard_tunnel.dll");
    logFileStatus(fallbackTunnelPath, "tunnel.dll");
    logFileStatus(wintunPath, "wintun.dll");
    logFileStatus(wireguardDriverPath, "wireguard.dll");
    logFileStatus(awgPath, "awg.exe");
}

void WireGuardTunnelManager::logServiceStatus(const std::string& context) {
    if (!serviceHandle) {
        std::cout << "WireGuardTunnelManager: Service status [" << context << "] handle=null" << std::endl;
        return;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            serviceHandle,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded)) {
        std::cerr << "WireGuardTunnelManager: Failed to query service status [" << context
                  << "]. Error: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "WireGuardTunnelManager: Service status [" << context << "]"
              << " current_state=" << status.dwCurrentState
              << " win32_exit=" << status.dwWin32ExitCode
              << " service_exit=" << status.dwServiceSpecificExitCode
              << " checkpoint=" << status.dwCheckPoint
              << " wait_hint=" << status.dwWaitHint
              << " pid=" << status.dwProcessId
              << std::endl;

    if (status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR &&
        status.dwServiceSpecificExitCode != 0) {
        std::cerr << "WireGuardTunnelManager: Service-specific failure [" << context
                  << "] reason="
                  << wireGuardServiceErrorToString(status.dwServiceSpecificExitCode)
                  << std::endl;
    }
}

void WireGuardTunnelManager::logAdapterSnapshot(const std::string& context) {
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = nullptr;
    ULONG result = ERROR_BUFFER_OVERFLOW;

    while (result == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(bufferSize));
        if (!addresses) {
            std::cerr << "WireGuardTunnelManager: Failed to allocate adapter buffer" << std::endl;
            return;
        }

        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            NULL,
            addresses,
            &bufferSize);
    }

    if (result != NO_ERROR) {
        std::cerr << "WireGuardTunnelManager: Adapter snapshot [" << context
                  << "] GetAdaptersAddresses failed: " << result << std::endl;
        free(addresses);
        return;
    }

    std::cout << "WireGuardTunnelManager: Adapter snapshot [" << context << "]" << std::endl;
    int loggedCount = 0;
    for (PIP_ADAPTER_ADDRESSES current = addresses; current != nullptr; current = current->Next) {
        std::wstring description = current->Description ? current->Description : L"";
        std::wstring friendlyName = current->FriendlyName ? current->FriendlyName : L"";
        if (description.find(L"Amnezia") == std::wstring::npos &&
            friendlyName.find(L"Amnezia") == std::wstring::npos &&
            description.find(L"WireGuard") == std::wstring::npos &&
            friendlyName.find(L"WireGuard") == std::wstring::npos &&
            description.find(L"Wintun") == std::wstring::npos &&
            friendlyName.find(L"Wintun") == std::wstring::npos) {
            continue;
        }

        std::ostringstream line;
        line << "  adapter[" << loggedCount << "]"
             << " name=" << narrow(friendlyName)
             << " description=" << narrow(description)
             << " oper_status=" << operStatusToString(current->OperStatus)
             << " if_index=" << current->IfIndex;

        if (current->FirstUnicastAddress &&
            current->FirstUnicastAddress->Address.lpSockaddr &&
            current->FirstUnicastAddress->Address.lpSockaddr->sa_family == AF_INET) {
            char ipBuffer[INET_ADDRSTRLEN] = {};
            sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(
                current->FirstUnicastAddress->Address.lpSockaddr);
            InetNtopA(AF_INET, &addr->sin_addr, ipBuffer, sizeof(ipBuffer));
            line << " ipv4=" << ipBuffer;
        }

        std::cout << line.str() << std::endl;
        loggedCount++;
    }

    if (loggedCount == 0) {
        std::cout << "  no Amnezia/WireGuard/Wintun adapters detected" << std::endl;
    }

    free(addresses);
}

} // namespace amnezia_flutter
