#include <QCoreApplication>
#include <QDebug>
#include <QByteArray>
#include <QString>

#include "ConnectionMapping.h"

int main(int argc, char *argv[]) {
    ConnectionMapping mapping = ConnectionMapping("./static");
    mapping.parseAll();

    //Отправить данные НЕ мнемокадр
    QString qstr = "Something info";
    QByteArray byteArray = qstr.toUtf8();
    u_char* ucharArray = new u_char[byteArray.size()];
    memcpy(ucharArray, byteArray.data(), byteArray.size());
    const u_char* packet = reinterpret_cast<const u_char *>(ucharArray);
    bool is_mnemocadr = false;
    mapping.send("Imp1", is_mnemocadr, packet);

    //Отправить данные Мнемокадр
//    u_char *mnemo_packet = ConnectionMapping::createMnemocadrData(statusRSU,              //uint8_t -  Статус РСУ
//                                                                  impellerStatuses,       //map<std::string, uint_8> с ключом вида "impellerStatus_i" - Статус импеллера № i (1-18)
//                                                                  impellerRelRotSpeeds,   //map<std::string, double> с ключом вида "relSpeed_i" - Относительное значение частоты вращения импеллера № i (1-18)
//                                                                  impellerAbsRotSpeeds,   //map<std::string, double> с ключом вида "absSpeed_i" - Абсолютное значение частоты вращения № i (1-18)
//                                                                  leftRUPosition,         //double - Положение левой РУ РСУ
//                                                                  rightRUPosition,        //double - Положение правой РУ РСУ
//                                                                  leftOZKRelSetpoint,     //double - Относительное значение уставки от СУ РСУ по суммарной частоте вращения импеллеров левого ОЗК
//                                                                  rightOZKRelSetpoint,    //double - Относительное значение уставки от СУ РСУ по суммарной частоте вращения импеллеров правого ОЗК
//                                                                  leftOZKAbsSpeed,        //double - Абсолютное значение суммарной частоты вращения импеллеров левого ОЗК
//                                                                  rightOZKAbsSpeed,       //double - Абсолютное значение суммарной частоты вращения импеллеров правого ОЗК
//                                                                  leftOZKDeviation,       //double - Абсолютное значение отклонения суммарной частоты вращения импеллеров левого ОЗК от заданного значения
//                                                                  rightOZKDeviation,      //double - Абсолютное значение отклонения суммарной частоты вращения импеллеров правого ОЗК от заданного значения
//                                                                  leftImpellerConnectionStatuses, //map<std::string, uint8_t> с ключом вида "leftImpellerConnectionStatus_i" - Статус подключения импеллера №i (1-18) и левого РУ
//                                                                  rightImpellerConnectionStatuses, //map<std::string, uint8_t> c ключом вида "rightImpellerConnectionStatus_i" - Статус подключения импеллера №i (1-18) и правого РУ
//                                                                  rsuMode,                //uint8_t - Идентификатор режима работы РСУ
//                                                                  akbChargeLevel,         //double - Уровень заряда АКБ
//                                                                  akbDischargeCurrent,    //double - Ток разряда АКБ
//                                                                  akbTemperature,         //double - Температура АКБ
//                                                                  sesVoltage,             //double - Значение электрического напряжения в системе электроснабжения (СЭС)
//                                                                  dateTime);              //uint32_t - Дата и время
//
//    mapping.send("...", true, mnemo_packet);
//
//
//

    //Принять данные (на другом сервере)
    ReceivedPacket res_packet = mapping.receive("Imp1");
    if (res_packet.is_received) {
        std::string stdstring(reinterpret_cast<const char*>(res_packet.payload), res_packet.size);
        QString res = QString::fromStdString(stdstring);
    } else {
        std::cout << "Packet is not capture" << "\n";
    }


}