#include <cstdint>
#include <cstring>
#include <vector>
#include <iostream>
#include <iomanip>
#include <string> 
#include <sstream> 
#include <stdio.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netpacket/packet.h>

using namespace std;

typedef struct filteredPacket_s{
    int packetNumber;

    sockaddr_ll mac_src;
    sockaddr_ll mac_dst;
    int macPacketSize;
    int macDataSize;
    int macHeaderSize;

    // ipVersion ipHeaderVersion; //use later when needed

    bool mac_set;
    in_addr ipv4_src;
    in_addr ipv4_dst;
    int ipv4PacketSize;
    int ipv4DataSize;

    bool ipv4_set;

    in6_addr ipv6_src;
    in6_addr ipv6_dst;
    int ipv6PacketSize;
    int ipv6DataSize;
    bool ipv6_set;

    // ipNextHeaderProtocol next_prot; //use later when needed

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
    vector<sockaddr_ll> mac;
    vector<in_addr> ipv4;
    vector<in6_addr> ipv6;
    vector<uint16_t> port;
    bool applySrc;
    bool applyDst;
} filter_t;

bool filterTypeCompare(filterTypeEnum &actualType, vector<filterTypeEnum> type){
    //Write func Description here
}

bool macsChecker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
}

bool ipv4Checker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
}

bool ipv6Checker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
}

bool portChecker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
}

bool filterChecker(filter_t& filter, filteredPacket_t& actualPacket, filterTypeEnum actualType,
                   vector<filteredPacket_t>& filteredPacketVec) {
    if(filterTypeCompare(actualType, filter.type)) {
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