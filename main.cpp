#include <QCoreApplication>
#include <QDebug>
#include <QByteArray>
#include <QString>

#include "ConnectionMapping.h"

int main(int argc, char *argv[]) {
    ConnectionMapping mapping = ConnectionMapping("./static");
    mapping.parseAll();

    //Отправить данные
    QString qstr = "Something info";
    QByteArray byteArray = qstr.toUtf8();
    u_char* ucharArray = new u_char[byteArray.size()];
    memcpy(ucharArray, byteArray.data(), byteArray.size());
    const u_char* packet = reinterpret_cast<const u_char *>(ucharArray);
    mapping.send("Imp1", packet);


    //Принять данные (на другом сервере)
    ReceivedPacket res_packet = mapping.receive("Imp1");
    if (res_packet.is_received) {
        std::string stdstring(reinterpret_cast<const char*>(res_packet.payload), res_packet.size);
        QString res = QString::fromStdString(stdstring);
    } else {
        std::cout << "Packet is not capture" << "\n";
    }


}