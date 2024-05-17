#include "PcapHandler.h"

ethernet_header PcapHandler::constructEthernetHeader(const std::string &src_mac, const std::string &dest_mac) {
    ethernet_header header{};
    sscanf(dest_mac.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
           &header.dest_mac[0], &header.dest_mac[1], &header.dest_mac[2],
           &header.dest_mac[3], &header.dest_mac[4], &header.dest_mac[5]);

    sscanf(src_mac.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
           &header.src_mac[0], &header.src_mac[1], &header.src_mac[2],
           &header.src_mac[3], &header.src_mac[4], &header.src_mac[5]);

    header.ether_type = htons(0x0800); // IPv4

    return header;
}

ip_header PcapHandler::constructIpHeader(const std::string &src_ip, const std::string &dest_ip, size_t payloadSize) {
    ip_header header{};

    header.version_and_header_length = 0x45;
    header.type_of_service = 0;
    header.total_length = htons(sizeof(ip_header) + sizeof(udp_header) + payloadSize);
    header.identification = 0;
    header.flags_and_fragment_offset = 0;
    header.time_to_live = 128;
    header.protocol = IPPROTO_UDP;
    header.header_checksum = 0;

    #if defined(_WIN64) || defined(_WIN32)
        header.src_ip_addr[0] = inet_addr(src_ip.c_str());
        header.dest_ip_addr[0] = inet_addr(dest_ip.c_str());
    #else
        inet_pton(AF_INET, src_ip.c_str(), header.src_ip_addr);
        inet_pton(AF_INET, dest_ip.c_str(), header.dest_ip_addr);
    #endif

    return header;
}

udp_header PcapHandler::constructUdpHeader(const int src_port, const int dest_port, size_t payload_size) {
    udp_header header{};
    header.src_port = htons(src_port);
    header.dest_port = htons(dest_port);
    header.length = htons(sizeof(udp_header) + payload_size);
    header.checksum = 0;

    return header;
}

void PcapHandler::constructUdpBuffer(u_char *packet_buffer, ethernet_header &eth_header, ip_header &ip_header,
                                     udp_header &udp_header, const u_char *payload, size_t payload_size) {
    memcpy(packet_buffer, &eth_header, sizeof(ethernet_header));
    memcpy(packet_buffer + sizeof(ethernet_header), &ip_header, sizeof(ip_header));
    memcpy(packet_buffer + sizeof(ethernet_header) + sizeof(ip_header), &udp_header, sizeof(udp_header));
    memcpy(packet_buffer + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header), payload, payload_size);
}

bool PcapHandler::openChannel(const std::string &iface_name) {
    this->interfaceName = iface_name;
    this->handle = pcap_open_live(iface_name.c_str(), 65536, 1, 7000, this->errbuf);
    if (handle == nullptr) return false;

    if (pcap_lookupnet(iface_name.c_str(), &this->net, &this->mask, errbuf) == -1) {
        std::cerr << "Error in obtaining the IP address and subnet mask for the device " << iface_name << ": " << errbuf << std::endl;
        return false;
    }

    return true;
}

bool PcapHandler::setReadFilter(int port_for_read) {
    std::string filter_expression = "udp port " + std::to_string(port_for_read);
    if (pcap_compile(this->handle, &this->filter, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Error compiling filter: " << pcap_geterr(this->handle) << std::endl;
        return false;
    }

    if (pcap_setfilter(this->handle, &this->filter) < 0) {
        std::cerr << "Error setting filter: " << pcap_geterr(this->handle) << std::endl;
        return false;
    }

    return true;
}

int PcapHandler::read(u_char* packet) {
    struct pcap_pkthdr* header;
    const u_char* data;

    int res = pcap_next_ex(this->handle, &header, &data);

    if (res > 0) {
        memcpy(packet, data, header->caplen);
        return 1;
    } else {
        return -1;
    }
}

void PcapHandler::write(const std::string &src_ip, const std::string &dest_ip, const std::string &src_mac,
                        const std::string &dest_mac, const int src_port, const int dest_port, const u_char *payload) {
    size_t payload_size = strlen(reinterpret_cast<const char*>(payload));

    ethernet_header eth_header = constructEthernetHeader(src_mac, dest_mac);
    ip_header ip_header = constructIpHeader(src_ip, dest_ip, payload_size);
    udp_header udp_header = constructUdpHeader(src_port, dest_port, payload_size);

    u_char packet_buffer[sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) + payload_size];
    constructUdpBuffer(packet_buffer, eth_header, ip_header, udp_header, payload, payload_size);

    if (pcap_sendpacket(this->handle, reinterpret_cast<const uint8_t*>(packet_buffer), sizeof(packet_buffer)) != 0) {
        std::cerr << "Error sending packet: " << pcap_geterr(this->handle) << std::endl;
    }
}

void PcapHandler::close_channel() {
    if (handle != nullptr) {
        pcap_freecode(&this->filter);
        pcap_close(handle);
        handle = nullptr;
        interfaceName.clear();
    }
}

char *PcapHandler::iptos(u_long in) {
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

std::string PcapHandler::getIpInfo(pcap_if_t *d) {
    pcap_addr_t *a;
    std::string result;
    for(a=d->addresses;a;a=a->next)
    {
        if (a->addr->sa_family == AF_INET && a->addr)
        {
            result = std::string(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        }
    }
    return result;
}


