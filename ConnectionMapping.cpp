#include<iostream>
#include<fstream>
#include<string>
#include<vector>
#include<unordered_map>

#include "ConnectionMapping.h"

std::vector<std::string> ConnectionMapping::split(const std::string& string_for_split, char delimiter) {
    std::vector<std::string> to_return;

    int start, end;
    start = end = 0;

    while ((start = string_for_split.find_first_not_of(delimiter, end)) != std::string::npos) {
        end = string_for_split.find(delimiter, start);
        to_return.push_back(string_for_split.substr(start, end - start));
    }

    return to_return;
}

void ConnectionMapping::parseConfig() {
    std::string path_to_config = path_to_directory + "/Config.txt";

    std::fstream in(path_to_config);

    if (in.is_open()) {
        int cnt = 0;
        std::string cur_config;
        while (std::getline(in, cur_config)) {
            clearBack(cur_config, '\r');
            cnt++;
            if (cnt == 1) {
                this->subnet = cur_config;
                continue;
            }

            std::vector<std::string> config_params = split(cur_config, ' ');

            this->config.push_back(std::make_tuple(config_params[1], //MAC-address
                                                   config_params[2])); //src device
            this->ipToRealName[this->subnet + config_params[0]] = "";
        }
    }

    in.close();

    for (pcap_if_t *d = this->handler.alldevs; d != nullptr; d = d->next) {
        std::string device_ip = PcapHandler::getIpInfo(d);
        if (this->ipToRealName.count(device_ip) > 0) {
            this->ipToRealName[device_ip] = d->name;
        }
    }
}

void ConnectionMapping::parseModels() {
    std::string path_to_models = path_to_directory + "/Models.txt";

    std::fstream in(path_to_models);

    if (in.is_open()) {

        std::string cur_model;
        while (std::getline(in, cur_model)) {
            clearBack(cur_model, '\r');
            std::vector<std::string> model_params = split(cur_model, ' ');

            this->models[model_params[0]] = std::make_tuple(model_params[1], //number trans interface
                                                            model_params[2], //number receive interface
                                                            model_params[3]); //udp-port
        }

    }

    in.close();
}

void ConnectionMapping::parseNames() {
    std::string path_to_names = path_to_directory + "/Names.txt";

    std::fstream in(path_to_names);

    if (in.is_open()) {

        int cnt = 0;
        std::string cur_name;
        while (std::getline(in, cur_name)) {
            cnt++;
            if (cnt == 1) {
                continue;
            }

            clearBack(cur_name, '\r');
            this->names.push_back(cur_name);
        }
    }

    in.close();
}

std::string ConnectionMapping::clearBack(std::string &string_for_clear, char) {
    if (!string_for_clear.empty() && string_for_clear.back() == '\r') {
        string_for_clear.pop_back();
    }

    return string_for_clear;
}

std::unordered_map<std::string, std::string>
ConnectionMapping::getMapping(std::string dest_device) {
    std::unordered_map<std::string, std::string> to_return;

    to_return["status"] = "true";
    if (this->models.find(dest_device) == this->models.end()) {
        to_return["status"] = "false";
        return to_return;
    }

    std::tuple<std::string, std::string, std::string> src_model_data = this->models[dest_device]; //Получаем информацию из Models, через какие интерфейсы и порт передаёт и получает информацию Модель
    std::string _ = std::get<0>(src_model_data); //интерефейс для отправления пакетов
    std::string receive_interface = std::get<1>(src_model_data); //интерефейс для принятия пакетов
    std::string using_port = std::get<2>(src_model_data); //используемый порт для обмена пакетами

    std::tuple<std::string, std::string> dest_config = this->config[std::stoi(receive_interface) - 1]; // получаем сетевый настройки интерефейся для получения пакетов "receive_interface"
    to_return["dest_MAC"] = std::get<0>(dest_config);
    to_return["dest_IP"] = this->subnet + receive_interface;
    to_return["dest_port"] = using_port;
    to_return["dest_name"] = this->names[std::stoi(receive_interface) - 1];
    std::string src_interface = std::get<1>(dest_config);

    std::tuple<std::string, std::string> src_config = this->config[std::stoi(src_interface) - 1];
    to_return["src_MAC"] = std::get<0>(src_config);
    to_return["src_IP"] = this->subnet + src_interface;
    to_return["src_port"] = using_port;
    to_return["src_name"] = this->names[std::stoi(src_interface) - 1];

    return to_return;
}



int ConnectionMapping::send(const std::string dest_model, const u_char *data) {
    std::unordered_map<std::string, std::string> mapping = this->getMapping(dest_model);

    if(mapping["status"] == "false") {
        return -1;
    }

    if (this->ipToRealName.find(mapping["src_IP"]) == this->ipToRealName.end())
    {
        return -1;
    } else {
        if (!this->handler.openChannel(this->ipToRealName[mapping["src_IP"]])) {
            return -1;
        }
    }

    this->handler.write(mapping["src_IP"], mapping["dest_IP"], mapping["src_MAC"], mapping["dest_MAC"], std::stoi(mapping["src_port"]), std::stoi(mapping["dest_port"]), data);

    this->handler.closeChannel();

    return 0;
}

int ConnectionMapping::receive(const std::string dest_model, u_char* packet) {
    std::unordered_map<std::string, std::string> mapping = this->getMapping(dest_model);

    if(mapping["status"] == "false") {
        return -1;
    }

    if (this->ipToRealName.find(mapping["src_IP"]) == this->ipToRealName.end())
    {
        return -1;
    } else {
        if (!this->handler.openChannel(this->ipToRealName[mapping["dest_IP"]])) {
            return -1;
        }
    }

    this->handler.setReadFilter(std::stoi(mapping["dest_port"]));

    int res = this->handler.read(packet);
    this->handler.closeChannel();
    return res;
}

void ConnectionMapping::parseAll() {
    this->parseConfig();
    this->parseNames();
    this->parseModels();
}






