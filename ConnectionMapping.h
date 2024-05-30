#include<iostream>
#include<string>
#include<vector>
#include<tuple>
#include<unordered_map>
#include"PcapHandler.h"

#if defined(_WIN64) || defined(_WIN32)
#include <Winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#endif


#ifndef CONN_MAPPING_CONNECTIONMAPPING_H
#define CONN_MAPPING_CONNECTIONMAPPING_H


class ConnectionMapping {


private:
    std::string path_to_directory;
    std::string subnet;

    std::vector<std::tuple<std::string, std::string>> config;
    std::unordered_map<std::string, std::tuple<std::string, std::string, std::string>> models;
    std::vector<std::string> names;

    std::unordered_map<std::string, std::string> ip_to_real_name;

    PcapHandler handler;

    static std::vector<std::string> split(const std::string& string_for_split, char delimiter);

    static std::string clearBack(std::string& string_for_clear, char);

    std::unordered_map<std::string, std::string> getMapping(std::string dest_device);


public:
    ConnectionMapping(std::string path_to_directory) : path_to_directory(path_to_directory) {};

    void parseConfig();

    void parseNames();

    void parseModels();

    void parseAll();

    int send(const std::string dest_model, const u_char* data);

    int receive(const std::string dest_model, u_char* packet);
};


#endif //CONN_MAPPING_CONNECTIONMAPPING_H
