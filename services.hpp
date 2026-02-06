#pragma once
#include <string>
#include <cstdint>

namespace netscanner {

enum class Service { UNKNOWN, HTTP, HTTPS, SSH, RDP, TELNET, FTP, SMTP, DNS };

struct PortServiceInfo {
    uint16_t port;
    Service identifiedService;
    std::string banner;
};

std::string service_to_string(Service s);
}
