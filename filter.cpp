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
#include <pcap.h>

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

void process_packet(const struct pcap_pkthdr* header, const u_char* packet_data) {
    // You can process or print the packet data here
    printf("Packet Length: %d\n", header->len);

    // Print the packet data as hexadecimal bytes
    for (int i = 0; i < header->len; i++) {
        printf("%02X ", packet_data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); // Newline after every 16 bytes
        }
    }
    printf("\n");
}

bool pcap_analyser_tcp(){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("custom_packets.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            // cout<<"HI"<<endl;
            // cout<<packet<<endl;
            // Process packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {

            // Timeout elapsed (if required)
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            // cout<<"hoho"<<endl;
            process_packet(header, packet);
            break;
        }
    }
    pcap_close(handle);
    return 1;
}


bool filterTypeCompare(filterTypeEnum &actualType, vector<filterTypeEnum> type){
    //Write func Description here
    return 0;
}

bool macsChecker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
    return 0;
}

bool ipv4Checker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
    return 0;
}

bool ipv6Checker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
    return 0;
}

bool portChecker(filteredPacket_t& actualPacket, filter_t& filter){
    //Write func Description here
    return 0;
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

int main(){
    bool k=pcap_analyser_tcp();
}