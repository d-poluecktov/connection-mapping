#include <QCoreApplication>
#include <QDebug>
#include "unordered_map"
#include "pcap.h"

#include "ConnectionMapping.h"

int main(int argc, char *argv[]) {
    //QCoreApplication a(argc, argv);
    //qDebug() << "Hello World";
    //return QCoreApplication::exec();


    ConnectionMapping mapping = ConnectionMapping("./static"); // Указать путь до файлов
    mapping.parseAll();

    const u_char *packet_for_send = reinterpret_cast<const u_char *>(argv[2]);


    mapping.send("GUI", "BMS2", packet_for_send); //Отправить пакет

    u_char *packet_for_receive = new u_char[60];
    mapping.receive("GUI", "BMS2", packet_for_receive); // Принять пакет
}
