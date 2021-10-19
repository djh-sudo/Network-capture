#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    /*
      * pls modify the shark.pro:
      * INCLUDEPATH += yourpath/Include
      * LIBS += your path/Lib/wpcap.lib  libws2_32
      * or IDE will warn you can't find some headerfiles!
      * this step helps us to add winpcap to our project actually
   */
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("Shark - @copyright by DJH 2021");
    w.show();
    return a.exec();
}
