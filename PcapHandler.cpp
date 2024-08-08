#include "PcapHandler.h"

EthernetHeader PcapHandler::constructEthernetHeader(const std::string &src_mac_str, const std::string &dest_mac_str) {
    EthernetHeader header;

    std::array<uint8_t, 6> dest_mac = macStringToBytes(dest_mac_str);
    std::array<uint8_t, 6> src_mac = macStringToBytes(src_mac_str);

    std::copy(dest_mac.begin(), dest_mac.end(), header.dest_mac);
    std::copy(src_mac.begin(), src_mac.end(), header.src_mac);

    header.ether_type = htons(0x0800);

    return header;
}

IPHeader PcapHandler::constructIpHeader(const std::string &src_ip, const std::string &dest_ip, size_t payload_size) {
    IPHeader header{};

    header.version_and_header_length = 0x45;
    header.type_of_service = 0;
    header.total_length = htons(sizeof(IPHeader) + sizeof(UDPHeader) + payload_size);
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

UDPHeader PcapHandler::constructUdpHeader(const int src_port, const int dest_port, size_t payload_size) {
    UDPHeader header{};
    header.src_port = htons(src_port);
    header.dest_port = htons(dest_port);
    header.length = htons(sizeof(UDPHeader) + payload_size);
    header.checksum = 0;

    return header;
}

void PcapHandler::constructUdpBuffer(u_char *packet_buffer, EthernetHeader &eth_header, IPHeader &ip_header,
                                     UDPHeader &udp_header, const u_char *payload, size_t payload_size) {
    //udp_header.checksum = checksum((unsigned short*) packet_buffer, ip_header, udp_header, payload_size);
    memcpy(packet_buffer, &eth_header, sizeof(EthernetHeader));
    memcpy(packet_buffer + sizeof(eth_header), &ip_header, sizeof(ip_header));
    memcpy(packet_buffer + sizeof(eth_header) + sizeof(ip_header), &udp_header, sizeof(udp_header));
    memcpy(packet_buffer + sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header), payload, payload_size);
}

bool PcapHandler::openChannel(const std::string &iface_name) {
    this->interface_name = iface_name;
    this->handle = pcap_open_live(iface_name.c_str(), 65536, 1, 1000, this->errbuf);
    if (handle == nullptr) return false;

    if (pcap_lookupnet(iface_name.c_str(), &this->net, &this->mask, errbuf) == -1) {
        return false;
    }

    return true;
}

bool PcapHandler::setReadFilter(int port_for_read) {
    std::string filter_expression = "udp port " + std::to_string(port_for_read);
    if (pcap_compile(this->handle, &this->filter, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
        return false;
    }

    if (pcap_setfilter(this->handle, &this->filter) < 0) {
        return false;
    }

    return true;
}

ReceivedPacket PcapHandler::read() {
    std::map<size_t, std::vector<u_char>> fragments;
    size_t total_fragments = 0;
    size_t current_fragment = 0;

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* data;

        //Принимаем очередной пакет
        int res = pcap_next_ex(this->handle, &header, &data);

        if (res <= 0) {
            ReceivedPacket null_packet;
            null_packet.size = 0;
            null_packet.payload = NULL;
            null_packet.is_received = false;
            return null_packet;
        }

        //Извлечение метаданных и подезной нагрузки

        //Смещение на фрейм Ethernet-а
        const size_t ETHERNET_SHIFT = 42;

        //Смещение к расположению полезной нагрузки
        const size_t SHIFT_TO_PAYLOAD = ETHERNET_SHIFT + 2*sizeof(size_t);

        //Извлекаем информацию об общем количества передаваемых пакетов
        size_t fragment_total = *reinterpret_cast<const size_t*>(data + ETHERNET_SHIFT);
        //Извлекаем информацию об индексе текущего переданного пакета
        size_t fragment_index = *reinterpret_cast<const size_t*>(data + ETHERNET_SHIFT + sizeof(size_t));

        const u_char* fragment_data = data + SHIFT_TO_PAYLOAD;
        size_t fragment_size = header->caplen - SHIFT_TO_PAYLOAD;

        //Запоминаем суммарное значение переданных пакетов
        if (total_fragments == 0) {
            total_fragments = fragment_total;
        }

        // Сохранение фрагмент под своим индексом
        fragments[fragment_index] = std::vector<u_char>(fragment_data, fragment_data + fragment_size);
        current_fragment++;

        //Проверяем, все ли фрагменты получены. Если да, то выходим
        if (current_fragment == total_fragments) {
            break;
        }
    }

    //Собираем полностью переданные данные
    std::vector<u_char> full_message;
    for (size_t i = 0; i < total_fragments; ++i) {
        full_message.insert(full_message.end(), fragments[i].begin(), fragments[i].end());
    }

    size_t message_size = full_message.size();
    auto* complete_message = new u_char[message_size];
    memcpy(complete_message, full_message.data(), message_size);

    ReceivedPacket to_return;
    to_return.size = message_size;
    to_return.payload = complete_message;
    to_return.is_received = true;
    return to_return;
}

void PcapHandler::write(const std::string &src_ip, const std::string &dest_ip, const std::string &src_mac,
                        const std::string &dest_mac, const int src_port, const int dest_port, const u_char *payload, bool is_mnemocadr) {
    size_t payload_size;
    if (is_mnemocadr) {
        payload_size = 444;
    } else {
        payload_size = strlen(reinterpret_cast<const char*>(payload));
    }


    size_t max_fragment_size = 1000;

    size_t total_fragments = (payload_size + max_fragment_size - 1) / max_fragment_size;


    for (size_t fragment_index = 0; fragment_index < total_fragments; ++fragment_index) {
        size_t fragment_offset = fragment_index * max_fragment_size;
        size_t fragment_size = std::min(max_fragment_size, payload_size - fragment_offset);

        std::vector<u_char> fragment_payload;
        fragment_payload.reserve(fragment_size + 2 * sizeof(size_t));


        //Добавление информации об общем отсылаемом количестве фрагментов
        fragment_payload.insert(fragment_payload.end(), reinterpret_cast<const u_char*>(&total_fragments), reinterpret_cast<const u_char*>(&total_fragments) + sizeof(size_t));
        //Добавление информации об текущем номере передаваемого фрагмента
        fragment_payload.insert(fragment_payload.end(), reinterpret_cast<const u_char*>(&fragment_index), reinterpret_cast<const u_char*>(&fragment_index) + sizeof(size_t));

        // Добавление части полезной нагрузки к фрагменту
        fragment_payload.insert(fragment_payload.end(), payload + fragment_offset, payload + fragment_offset + fragment_size);

        EthernetHeader eth_header = constructEthernetHeader(src_mac, dest_mac);
        IPHeader ip_header = constructIpHeader(src_ip, dest_ip, fragment_payload.size());
        UDPHeader udp_header = constructUdpHeader(src_port, dest_port, fragment_payload.size());

        std::vector<u_char> packet_buffer(sizeof(EthernetHeader) + sizeof(ip_header) + sizeof(udp_header) + fragment_payload.size());
        constructUdpBuffer(packet_buffer.data(), eth_header, ip_header, udp_header, fragment_payload.data(), fragment_payload.size());

        pcap_sendpacket(this->handle, packet_buffer.data(), packet_buffer.size());
    }
}

void PcapHandler::closeChannel() {
    if (handle != nullptr) {
        pcap_freecode(&this->filter);
        pcap_close(handle);
        handle = nullptr;
        interface_name.clear();
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

std::array<uint8_t, 6> PcapHandler::macStringToBytes(const std::string &mac) {
    std::array<uint8_t, 6> bytes;
    std::istringstream iss(mac);
    std::string byte_str;
    int i = 0;

    while (std::getline(iss, byte_str, '-') && i < 6) {
        int byte_val;
        std::istringstream(byte_str) >> std::hex >> byte_val;
        bytes[i++] = static_cast<uint8_t>(byte_val);
    }

    if (i != 6) {
        throw std::invalid_argument("Invalid MAC address format");
    }

    return bytes;
}

unsigned short PcapHandler::checksum(unsigned short *packet_buffer, IPHeader &ip_header, UDPHeader &udp_header, size_t payload_size) {
    unsigned short checksum_size = 0;
    checksum_size += sizeof(ip_header.src_ip_addr);
    checksum_size += sizeof(ip_header.dest_ip_addr);
    checksum_size += sizeof(ip_header.protocol);
    checksum_size += sizeof(udp_header.length);
    checksum_size += sizeof(udp_header);
    checksum_size += payload_size;

    unsigned long result = 0;
    while(checksum_size > 1)
    {
        result+=*packet_buffer++;
        checksum_size -= sizeof(unsigned short);
    }
    if(checksum_size)
        result+=*(unsigned short*)packet_buffer;
    result = (result >> 16 ) + (result & 0xffff);
    result += (result >> 16 );
    return (unsigned short) (~result);
}


