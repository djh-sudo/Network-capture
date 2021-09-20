#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "capture.h"
#include "readonlydelegate.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // construction and destruction
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // show network card
    void showNetworkCard();
    // capture the data package
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);
public slots:
    void handleMessage(DataPackage data);
private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // all adapter device
    pcap_if_t *device;                      // An adapter
    pcap_t *pointer;                        // data package pointer
    ReadOnlyDelegate* readOnlyDelegate;     // readonly detegate
    int countNumber;                        // countNumber
    int rowNumber;                          // rowNumber
    QVector<DataPackage>data;               // store data
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer
    bool isStart;                           // the thread is start or not
};
#endif // MAINWINDOW_H
