#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace netscanner {
std::vector<std::string> expand_cidr(const std::string &cidr);
uint32_t ipv4_to_u32(const std::string &ip);
std::string u32_to_ipv4(uint32_t v);
}
