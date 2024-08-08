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

            if (cur_config.empty()) {
                continue;
            }

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

            if (cur_model.empty()) {
                continue;
            }

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

            if (cur_name.empty()) {
                continue;
            }

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



int ConnectionMapping::send(const std::string dest_model, bool is_mnemocadr, const u_char *data) {
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

    this->handler.write(mapping["src_IP"], mapping["dest_IP"], mapping["src_MAC"], mapping["dest_MAC"],
                            std::stoi(mapping["src_port"]), std::stoi(mapping["dest_port"]), data, is_mnemocadr);

    this->handler.closeChannel();

    return 0;
}

ReceivedPacket ConnectionMapping::receive(const std::string dest_model) {
    std::unordered_map<std::string, std::string> mapping = this->getMapping(dest_model);

    if(mapping["status"] == "false") {
        ReceivedPacket null_packet;
        null_packet.size = 0;
        null_packet.payload = nullptr;
        null_packet.is_received = false;
        return null_packet;
    }

    if (this->ipToRealName.find(mapping["src_IP"]) == this->ipToRealName.end())
    {
        ReceivedPacket null_packet;
        null_packet.size = 0;
        null_packet.payload = nullptr;
        null_packet.is_received = false;
        return null_packet;
    } else {
        if (!this->handler.openChannel(this->ipToRealName[mapping["dest_IP"]])) {
            ReceivedPacket null_packet;
            null_packet.size = 0;
            null_packet.payload = nullptr;
            null_packet.is_received = false;
            return null_packet;
        }
    }

    this->handler.setReadFilter(std::stoi(mapping["dest_port"]));


    ReceivedPacket res = this->handler.read();
    this->handler.closeChannel();
    return res;
}

void ConnectionMapping::parseAll() {
    this->parseConfig();
    this->parseNames();
    this->parseModels();
}

u_char* ConnectionMapping::createMnemocadrData(uint8_t statusRSU,
                                            std::unordered_map<std::string, uint8_t> impellerStatuses,
                                            std::unordered_map<std::string, double> impellerRelRotSpeeds,
                                            std::unordered_map<std::string, double> impellerAbsRotSpeeds,
                                            double leftRUPosition,
                                            double rightRUPosition,
                                            double leftOZKRelSetpoint,
                                            double rightOZKRelSetpoint,
                                            double leftOZKAbsSpeed,
                                            double rightOZKAbsSpeed,
                                            double leftOZKDeviation,
                                            double rightOZKDeviation,
                                            std::unordered_map<std::string, uint8_t> leftImpellerConnectionStatuses,
                                            std::unordered_map<std::string, uint8_t> rightImpellerConnectionStatuses,
                                            uint8_t rsuMode,
                                            double akbChargeLevel,
                                            double akbDischargeCurrent,
                                            double akbTemperature,
                                            double sesVoltage,
                                            uint32_t dateTime) {
    u_char* buffer = new u_char[445]();

    // Статус РСУ
    buffer[0] = statusRSU;

    // Статусы импеллеров
    for (int i = 0; i < 18; ++i) {
        std::string key = "impellerStatus_" + std::to_string(i + 1);
        if (impellerStatuses.find(key) != impellerStatuses.end()) {
            buffer[1 + i] = impellerStatuses[key];
        }
    }

    // Относительные значения частоты вращения импеллеров
    for (int i = 0; i < 18; ++i) {
        std::string key = "relSpeed_" + std::to_string(i + 1);
        if (impellerRelRotSpeeds.find(key) != impellerRelRotSpeeds.end()) {
            double relSpeed = impellerRelRotSpeeds[key];
            std::memcpy(buffer + 19 + 8 * i, &relSpeed, sizeof(double));
        }
    }

    // Абсолютные значения частоты вращения импеллеров
    for (int i = 0; i < 18; ++i) {
        std::string key = "absSpeed_" + std::to_string(i + 1);
        if (impellerAbsRotSpeeds.find(key) != impellerAbsRotSpeeds.end()) {
            double absSpeed = impellerAbsRotSpeeds[key];
            std::memcpy(buffer + 163 + 8 * i, &absSpeed, sizeof(double));
        }
    }

    // Положение левой РУ РСУ
    std::memcpy(buffer + 307, &leftRUPosition, sizeof(double));
    // Положение правой РУ РСУ
    std::memcpy(buffer + 315, &rightRUPosition, sizeof(double));

    // Относительное значение уставки от СУ РСУ левого ОЗК
    std::memcpy(buffer + 323, &leftOZKRelSetpoint, sizeof(double));
    // Относительное значение уставки от СУ РСУ правого ОЗК
    std::memcpy(buffer + 331, &rightOZKRelSetpoint, sizeof(double));

    // Абсолютное значение суммарной частоты вращения импеллеров левого ОЗК
    std::memcpy(buffer + 339, &leftOZKAbsSpeed, sizeof(double));
    // Абсолютное значение суммарной частоты вращения импеллеров правого ОЗК
    std::memcpy(buffer + 347, &rightOZKAbsSpeed, sizeof(double));

    // Абсолютное значение отклонения суммарной частоты вращения импеллеров левого ОЗК от заданного значения
    std::memcpy(buffer + 355, &leftOZKDeviation, sizeof(double));
    // Абсолютное значение отклонения суммарной частоты вращения импеллеров правого ОЗК от заданного значения
    std::memcpy(buffer + 363, &rightOZKDeviation, sizeof(double));

    // Статусы подключения импеллеров и левого РУ
    for (int i = 0; i < 18; ++i) {
        std::string key = "leftImpellerConnectionStatus_" + std::to_string(i + 1);
        if (leftImpellerConnectionStatuses.find(key) != leftImpellerConnectionStatuses.end()) {
            buffer[371 + i] = leftImpellerConnectionStatuses[key];
        }
    }

    // Статусы подключения импеллеров и правого РУ
    for (int i = 0; i < 18; ++i) {
        std::string key = "rightImpellerConnectionStatus_" + std::to_string(i + 1);
        if (rightImpellerConnectionStatuses.find(key) != rightImpellerConnectionStatuses.end()) {
            buffer[389 + i] = rightImpellerConnectionStatuses[key];
        }
    }

    // Идентификатор режима работы РСУ
    buffer[407] = rsuMode;

    // Уровень заряда АКБ
    std::memcpy(buffer + 408, &akbChargeLevel, sizeof(double));

    // Ток разряда АКБ
    std::memcpy(buffer + 416, &akbDischargeCurrent, sizeof(double));

    // Температура АКБ
    std::memcpy(buffer + 424, &akbTemperature, sizeof(double));

    // Значение электрического напряжения в СЭС
    std::memcpy(buffer + 432, &sesVoltage, sizeof(double));

    // Дата и время
    std::memcpy(buffer + 440, &dateTime, sizeof(uint32_t));

    return buffer;
}





