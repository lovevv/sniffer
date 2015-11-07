#include "sniffer_ui.h"
#include "Packet_Format.h"
#include "my_sniffer.h"
#include <QApplication>
#include <QSplashScreen>
#include <QMainWindow>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    sniffer_ui w;
    w.show();

    return a.exec();
}
