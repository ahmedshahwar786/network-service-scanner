#include "services.hpp"
namespace netscanner {
std::string service_to_string(Service s) {
    switch (s) {
        case Service::HTTP: return "HTTP";
        case Service::HTTPS: return "HTTPS";
        case Service::SSH: return "SSH";
        case Service::RDP: return "RDP";
        case Service::TELNET: return "TELNET";
        case Service::FTP: return "FTP";
        case Service::SMTP: return "SMTP";
        case Service::DNS: return "DNS";
        default: return "UNKNOWN";
    }
}
}
