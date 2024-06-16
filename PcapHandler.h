#include <iostream>
#include <sstream>
#include <cstring>
#include <vector>
#include <map>
#include <pcap.h>



#if defined(_WIN64) || defined(_WIN32)
#include <Winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#endif



#ifndef CONN_MAPPING_PCAPHANDLER_H
#define CONN_MAPPING_PCAPHANDLER_H

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct IPHeader {
    uint8_t version_and_header_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t src_ip_addr[4];
    uint8_t dest_ip_addr[4];
};

struct ReceivedPacket {
    u_char* payload;
    size_t size;
    size_t is_received;
};


class PcapHandler {
private:
    #define IPTOSBUFFERS	30

    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE]{};

    struct bpf_program filter{};
    bpf_u_int32 net, mask;

    static std::array<uint8_t, 6> macStringToBytes(const std::string& mac);

    static EthernetHeader constructEthernetHeader(const std::string& src_mac_str, const std::string& dest_mac_str);

    static IPHeader constructIpHeader(const std::string& src_ip, const std::string& dest_ip, size_t payload_size);

    static UDPHeader constructUdpHeader(const int src_port, const int dest_port, size_t payload_size);

    static void constructUdpBuffer(u_char* packet_buffer, EthernetHeader &eth_header, IPHeader &ip_header, UDPHeader &udp_header, const u_char* payload, size_t payload_size);

    static char* iptos(u_long in);


public:
    pcap_if_t *alldevs;

    std::string interface_name;

    PcapHandler() : handle(nullptr) {
        if (pcap_findalldevs(&this->alldevs, this->errbuf) == -1) {
            std::cerr << "Failed in pcap_findalldevs: " << this->errbuf << std::endl;
        }
    }

    ~PcapHandler() {
        closeChannel();
    }

    static std::string getIpInfo(pcap_if_t *d);

    bool openChannel(const std::string& iface_name);

    bool setReadFilter(int port_for_read);

    ReceivedPacket read();

    void write(const std::string& src_ip, const std::string& dest_ip, const std::string& src_mac, const std::string& dest_mac, const int src_port, const int dest_port, const u_char* payload);

    void closeChannel();
};


#endif //CONN_MAPPING_PCAPHANDLER_H
