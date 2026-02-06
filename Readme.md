# Network Service Scanner (C++)

A lightweight, modular C++ network scanner designed for defensive cybersecurity auditing. The tool parses CIDR ranges, identifies live hosts, scans common TCP ports, and performs basic service fingerprinting using structured enums and banner/port mapping.

Built using object-oriented principles and separated modules to demonstrate clean architecture and secure tool development.

## Features

- CIDR range parsing (e.g., 192.168.1.0/24)  
- Live host discovery  
- TCP port scanning (22, 80, 443, 3389, etc.)  
- Basic service fingerprinting  
- Modular architecture using header/source files  
- Cross-platform (Windows & Linux)


## How It Works

1. User provides CIDR block  
2. CIDR parser expands subnet into usable IPs  
3. Scanner checks predefined TCP ports  
4. Services module maps ports or grabs banners  
5. Results printed in readable format  

## Screenshot


## How to Compile & Run (Linux / macOS)

g++ main.cpp cidr_parser.cpp scanner.cpp services.cpp -o scanner  
./scanner  

## How to Compile & Run (Windows - MinGW)

g++ main.cpp cidr_parser.cpp scanner.cpp services.cpp -o scanner.exe  
scanner.exe  

## Technologies Used

- C++ (Modern Standard)  
- Standard Library  
- Sockets API  

## Security Considerations

- Designed for defensive auditing  
- No exploitation features  
- Input validation implemented  
- Academic & internal security use  

## What I Learned

- CIDR parsing techniques  
- Socket programming  
- Modular C++ design  
- Service fingerprinting concepts  
- Secure tool development  

## Disclaimer

This project is for educational and defensive cybersecurity purposes only.
