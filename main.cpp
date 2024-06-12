#include <QCoreApplication>
#include <QDebug>
#include "unordered_map"
#include "pcap.h"

#include "ConnectionMapping.h"

int main(int argc, char *argv[]) {
    //QCoreApplication a(argc, argv);
    //qDebug() << "Hello World";
    //return QCoreApplication::exec();

    ConnectionMapping mapping = ConnectionMapping("./static"); // Указать путь до папки с файлами
    //Спарсить все файлы
    mapping.parseAll();

    const u_char *packet_for_send = reinterpret_cast<const u_char *>(argv[2]);


    //Предположим мы находимся на 3 сервере, хотим отправить на Imp1, необходимо указать получателя.
    int res_send = mapping.send("Imp1", packet_for_send); //Отправить пакет

    //Принять пакет со стороны Imp1 (на 1 сервер) передать указатель, куда скопируется содержимое пакета
    u_char* packet = mapping.receive("Imp1"); // Принять пакет
}