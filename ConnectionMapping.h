#include<fstream>
#include<unordered_map>
#include<vector>
#include<tuple>
#include<string>
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

    std::unordered_map<std::string, std::string> ipToRealName;

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

    int send(const std::string dest_model, std::string flag, const u_char* data);

    static u_char* createMnemocadrData(std::unordered_map<std::string, double> angularSpeeds, 
                                       std::unordered_map<std::string, int> statuses,         
                                       double ustl, double ustp,                              
                                       double tempAkb, double currentAkb, double voltageAkb,  
                                       double oTempAkb, double oCurrentAkb, double oVoltageAkb,
                                       int64_t timestamp );

    static u_char* createMnemocadrRUD(double leftRUDPosition, double rightRUDPosition);

    ReceivedPacket receive(const std::string dest_model);
};


#endif //CONN_MAPPING_CONNECTIONMAPPING_H
