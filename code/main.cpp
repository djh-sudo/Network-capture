#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("Shark - @copyright by DJH 2021");
    w.show();
    return a.exec();
}
