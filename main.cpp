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
    std::string flag = "";
    mapping.send("Imp1", "", packet);

    //Отправить данные Мнемокадр
    // u_char *mnemo_packet = ConnectionMapping::createMnemocadrData(angularSpeeds, //std::unordered_map<std::string, double> - угловые скорости с ключами вида "angularSpeed_LIi", "angularSpeed_PIi" - где i номер угловой скорости ЛИ и ПИ
    //                                                               statuses,      //std::unordered_map<std::string, int> - статусы с ключами вида "status_LIi", "status_PIi", "status_LKRUi", "status_PKRUi" - где i номер статуса 
    //                                                               ustl,          //double УСТЛ
    //                                                               ustp,          //double УСТП             
    //                                                               tempAkb,       //double Темп АКБ
    //                                                               currentAkb,    //double ТокАКБ
    //                                                               voltageAkb,    //double НапрАКБ
    //                                                               oTempAkb,      //double ОТемпАКБ
    //                                                               oCurrentAkb,   //double ОТокАКБ
    //                                                               oVoltageAkb,   //double ОНапрАКБ
    //                                                               timestamp);    //int64_t Время

    // mapping.send("...", "mnemocadr_data", mnemo_packet);  

    //Отправить RUD
    //u_char *mnemo_packet = ConnectionMapping::createMnemocadrRUD(leftRUDPosition,   //double Положение ЛРУД
    //                                                             rightRUDPosition); //double Положение ПРУД  
    // mapping.send("...", "mnemocadr_rud", mnemo_packet); 

    

    //Принять данные (на другом сервере)
    ReceivedPacket res_packet = mapping.receive("Imp1");
    if (res_packet.is_received) {
        std::string stdstring(reinterpret_cast<const char*>(res_packet.payload), res_packet.size);
        QString res = QString::fromStdString(stdstring);
    } else {
        std::cout << "Packet is not capture" << "\n";
    }


}