#include <iostream>
#include <sstream>
#include <vector>
#include "cidr_parser.hpp"
#include "scanner.hpp"
#include "services.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

using namespace netscanner;

int main(int argc, char** argv){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);

    if(argc<2){ std::cout<<"Usage: network-scanner <CIDR_or_IP> [ports]\n"; return 0; }

    std::string cidr = argv[1];
    std::vector<uint16_t> ports={22,80,443};
    if(argc>=3){
        ports.clear(); std::stringstream ss(argv[2]); std::string t;
        while(getline(ss,t,',')) try{ports.push_back((uint16_t)stoi(t));}catch(...){}
    }

    std::vector<std::string> hosts;
    try{
        if(cidr.find('/')==std::string::npos) hosts.push_back(cidr);
        else hosts=expand_cidr(cidr);
    }catch(const std::exception&e){ std::cerr<<"CIDR error: "<<e.what()<<'\n'; return 1; }

    Scanner sc(ports,2000,30);
    auto results=sc.scan_hosts(hosts);
    for(auto &r:results){
        std::cout<<"Host: "<<r.ip<<'\n';
        for(auto &p:r.ports)
            std::cout<<"  Port "<<p.port<<" - "<<service_to_string(p.identifiedService)
                     <<(p.banner.empty()?"":" banner: "+p.banner.substr(0,80))<<'\n';
        std::cout<<'\n';
    }
    WSACleanup(); 
    return 0;
}


