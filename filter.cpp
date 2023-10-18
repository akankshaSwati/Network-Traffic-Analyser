#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string> 
#include <sstream> 
#include <vector>
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

typedef struct filteredPacket_s{
    int packetNumber;

    mac_addr_t mac_src;
    mac_addr_t mac_dst;
    int macPacketSize;
    int macDataSize;
    int macHeaderSize;

    ipVersion ipHeaderVersion;

    bool mac_set;
    ipv4_addr_t ipv4_src;
    ipv4_addr_t ipv4_dst;
    int ipv4PacketSize;
    int ipv4DataSize;

    bool ipv4_set;

    ipv6_addr_t ipv6_src;
    ipv6_addr_t ipv6_dst;
    int ipv6PacketSize;
    int ipv6DataSize;
    bool ipv6_set;

    ipNextHeaderProtocol next_prot;

    uint16_t port_src;
    uint16_t port_dst;
    int tcpPacketSize;
    int tcpDataSize;
    int udpPacketSize;
    int udpDataSize;
    bool port_set;
} filteredPacket_t;

enum class filterTypeEnum {
    mac,
    ipv4,
    ipv6,
    tcp,
    udp
};

typedef struct filter_s{
    vector<filterTypeEnum> type;
    vector<mac_addr_t> mac;
    vector<ipv4_addr_t> ipv4;
    vector<ipv6_addr_t> ipv6;
    vector<uint16_t> port;
    bool applySrc;
    bool applyDst;
} filter_t;

bool filterChecker(filter_t& filter, filteredPacket_t& actualPacket, filterTypeEnum actualType,
                   vector<filteredPacket_t>& filteredPacketVec) {
    if(filterTypeCompare(actualType, filter.type)) {
        //cout << actualPacket.packetNumber << ": Looking on this type of header: " << filterTypeGiveString(actualType) << endl;

        switch (actualType) {
            case filterTypeEnum::mac:
                if(macsChecker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::ipv4:
                if(ipv4Checker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::ipv6:
                if(ipv6Checker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::tcp:
                if(portChecker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::udp:
                if(portChecker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
        }
        return true;
    }
    return false;
}