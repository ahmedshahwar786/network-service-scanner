#pragma once
#include <string>
#include <vector>
#include "services.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

namespace netscanner {

struct ScanResult {
    std::string ip;
    std::vector<PortServiceInfo> ports;
};

class Scanner {
public:
    Scanner(std::vector<uint16_t> ports, int timeout_ms = 3000, int max_threads = 50);
    std::vector<ScanResult> scan_hosts(const std::vector<std::string>& hosts);

private:
    std::vector<uint16_t> ports_;
    int timeout_ms_;
    int max_threads_;

    PortServiceInfo scan_port(const std::string &ip, uint16_t port);
    bool connect_with_timeout(SOCKET sock, const sockaddr_in &addr, int timeout_ms);
    Service identify_by_banner(uint16_t port, const std::string &banner);
};
}
