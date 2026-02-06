#include "cidr_parser.hpp"
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace netscanner {

uint32_t ipv4_to_u32(const std::string &ip) {
    IN_ADDR a{};
    if (InetPtonA(AF_INET, ip.c_str(), &a) != 1)
        throw std::runtime_error("Invalid IPv4 address: " + ip);
    return ntohl(a.S_un.S_addr);
}

std::string u32_to_ipv4(uint32_t v) {
    IN_ADDR a{};
    a.S_un.S_addr = htonl(v);
    char buf[INET_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET, &a, buf, sizeof(buf)))
        throw std::runtime_error("Failed to convert IP");
    return std::string(buf);
}

std::vector<std::string> expand_cidr(const std::string &cidr) {
    auto pos = cidr.find('/');
    if (pos == std::string::npos) throw std::runtime_error("CIDR missing '/'");
    std::string ipstr = cidr.substr(0, pos);
    int prefix = std::stoi(cidr.substr(pos + 1));
    if (prefix < 0 || prefix > 32) throw std::runtime_error("Invalid prefix");

    uint32_t ip = ipv4_to_u32(ipstr);
    uint32_t mask = prefix == 0 ? 0 : (~uint32_t(0) << (32 - prefix));
    uint32_t network = ip & mask;
    uint32_t broadcast = network | (~mask);

    std::vector<std::string> out;
    uint32_t first = network + 1;
    uint32_t last = broadcast - 1;
    if (prefix >= 31) {
        if (first <= last)
            for (uint32_t v = first; v <= last; ++v) out.push_back(u32_to_ipv4(v));
        return out;
    }
    for (uint32_t v = first; v <= last; ++v) out.push_back(u32_to_ipv4(v));
    return out;
}
}
