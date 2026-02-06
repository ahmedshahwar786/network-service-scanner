#include "scanner.hpp"
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

namespace netscanner {

static void close_socket(SOCKET s) { closesocket(s); }

Scanner::Scanner(std::vector<uint16_t> ports, int timeout_ms, int max_threads)
    : ports_(std::move(ports)), timeout_ms_(timeout_ms), max_threads_(max_threads) {}

Service Scanner::identify_by_banner(uint16_t port, const std::string &banner) {
    if (port == 80) return Service::HTTP;
    if (port == 443) return Service::HTTPS;
    if (port == 22) return Service::SSH;
    if (port == 3389) return Service::RDP;
    if (port == 23) return Service::TELNET;
    std::string b = banner;
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    if (b.find("ssh-") != std::string::npos) return Service::SSH;
    if (b.find("http") != std::string::npos) return Service::HTTP;
    if (b.find("ftp")  != std::string::npos) return Service::FTP;
    return Service::UNKNOWN;
}

bool Scanner::connect_with_timeout(SOCKET sock, const sockaddr_in &addr, int timeout_ms) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    int res = connect(sock, (const sockaddr*)&addr, sizeof(addr));
    if (res == 0) { mode = 0; ioctlsocket(sock, FIONBIO, &mode); return true; }
    int last = WSAGetLastError();
    if (last != WSAEWOULDBLOCK && last != WSAEINPROGRESS) return false;

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    timeval tv{ timeout_ms/1000, (timeout_ms%1000)*1000 };
    int sel = select(0, nullptr, &wfds, nullptr, &tv);
    if (sel > 0) {
        int so_error = 0; int len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        if (so_error == 0) { mode = 0; ioctlsocket(sock, FIONBIO, &mode); return true; }
    }
    return false;
}

PortServiceInfo Scanner::scan_port(const std::string &ip, uint16_t port) {
    PortServiceInfo info{port, Service::UNKNOWN, ""};
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return info;

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    InetPtonA(AF_INET, ip.c_str(), &addr.sin_addr);

    if (!connect_with_timeout(sock, addr, timeout_ms_)) { close_socket(sock); return info; }

    if (port == 80) {
        const char *req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        send(sock, req, (int)strlen(req), 0);
    }

    int recv_to = timeout_ms_;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_to, sizeof(recv_to));

    char buf[512]; int n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n > 0) { buf[n]=0; info.banner = buf; info.identifiedService = identify_by_banner(port, info.banner); }
    else info.identifiedService = identify_by_banner(port, "");
    close_socket(sock);
    return info;
}

std::vector<ScanResult> Scanner::scan_hosts(const std::vector<std::string>& hosts) {
    std::vector<ScanResult> results; std::mutex m; std::atomic<size_t> idx{0};
    auto worker = [&](){
        while(true){
            size_t i=idx.fetch_add(1); if(i>=hosts.size()) break;
            ScanResult sr; sr.ip = hosts[i];
            for(auto p:ports_){
                auto psi = scan_port(sr.ip,p);
                if(psi.identifiedService!=Service::UNKNOWN || !psi.banner.empty())
                    sr.ports.push_back(std::move(psi));
            }
            if(!sr.ports.empty()){ std::lock_guard<std::mutex> g(m); results.push_back(std::move(sr)); }
        }
    };
    int threads = std::min<int>(max_threads_, (int)hosts.size());
    std::vector<std::thread> pool; pool.reserve(threads);
    for(int t=0;t<threads;++t) pool.emplace_back(worker);
    for(auto &th:pool) th.join();
    return results;
}
}
