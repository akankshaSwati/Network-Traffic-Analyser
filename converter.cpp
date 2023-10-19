#include <iostream>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

#pragma pack(1)
struct IPHeader {
    uint8_t version_and_header_length;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    in_addr source_ip;
    in_addr dest_ip;
};

struct TCPHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t source_mac[6];
    uint16_t eth_type;
};

void write_pcap_file(const char* filename, vector<unsigned char>& packet_data) {
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t* dumper = pcap_dump_open(pcap, filename);
    pcap_pkthdr header;
    header.len = packet_data.size();
    header.caplen = packet_data.size();
    struct timeval tv;
    gettimeofday(&tv, NULL);
    header.ts = tv;
    pcap_dump((u_char*)dumper, &header, packet_data.data());
    pcap_dump_close(dumper);
    pcap_close(pcap);
}

int main() {
    ifstream input_file("input.txt");
    if (!input_file) {
        cerr << "Failed to open input file." << endl;
        return 1;
    }

    vector<unsigned char> packet_data;
    while (!input_file.eof()) {
        string line;
        while (line != "***********************TCP Packet*************************") {
            if (!getline(input_file, line)) {
                break;
            }
        }

        if (line != "***********************TCP Packet*************************") {
            break;
        }

        IPHeader ip_header;
        TCPHeader tcp_header;

        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file >> hex;
        input_file >> ip_header.version_and_header_length >> ip_header.tos;
        input_file >> ip_header.total_length >> ip_header.identification;
        input_file >> ip_header.flags_and_offset;
        input_file >> ip_header.ttl >> ip_header.protocol;
        input_file >> ip_header.checksum;
        input_file >> ip_header.source_ip.s_addr >> ip_header.dest_ip.s_addr;

        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file >> hex;
        input_file >> tcp_header.source_port >> tcp_header.dest_port;
        input_file >> tcp_header.sequence_number >> tcp_header.acknowledgment_number;
        input_file >> hex;
        input_file >> tcp_header.data_offset;
        input_file >> tcp_header.flags;
        input_file >> dec;
        input_file >> tcp_header.window >> tcp_header.checksum >> tcp_header.urgent_pointer;

        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file.ignore(numeric_limits<streamsize>::max(), '\n');
        input_file.ignore(numeric_limits<streamsize>::max(), '\n');

        string data;
        while (getline(input_file, line) && line != "###########################################################") {
            data += line;
        }

        packet_data.clear();

        // Add Ethernet header (14 bytes)
        EthernetHeader eth_header;
        memset(eth_header.dest_mac, 0xFF, 6);
        memset(eth_header.source_mac, 0x00, 6);
        eth_header.eth_type = htons(0x0800); // IP packet
        packet_data.insert(packet_data.end(), (unsigned char*)&eth_header, (unsigned char*)&eth_header + sizeof(eth_header));

        // Add IP header
        packet_data.insert(packet_data.end(), (unsigned char*)&ip_header, (unsigned char*)&ip_header + sizeof(ip_header));

        // Add TCP header
        packet_data.insert(packet_data.end(), (unsigned char*)&tcp_header, (unsigned char*)&tcp_header + sizeof(tcp_header));

        // Add Data payload
        for (size_t i = 0; i < data.length(); i += 2) {
            unsigned char byte = stoul(data.substr(i, 2), nullptr, 16);
            packet_data.push_back(byte);
        }

        // Write the packet to the pcap file
        write_pcap_file("output.pcap", packet_data);
    }

    input_file.close();
    return 0;
}
