#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>
#include <Format.h>
#include <QQueue>
#include "pcap.h"
#include <QString>
#include "winsock2.h"
#include "datapackage.h"

class Capture : public QThread
{
     Q_OBJECT
public:
    Capture();
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();
    int ethernetPackageHandle(const u_char *pkt_content,QString& info);
    int ipPackageHandle(const u_char *pkt_content,int&ipPackage);
    QString arpPackageHandle(const u_char *pkt_content);
    QString icmpPackageHandle(const u_char *pkt_content);
    int tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage);
    int udpPackageHandle(const u_char *pkt_content,QString&info);
    QString dnsPackageHandle(const u_char *pkt_content);
protected:
    static QString byteToHex(u_char *str, int size);
    void run();

signals:
    void send(DataPackage data);

private:
    pcap_t *pointer;
    struct pcap_pkthdr*header;
    const u_char *pkt_data;
    time_t local_time_version_sec;
    struct tm local_time;
    char timeString[16];
    volatile bool isDone;// done flag
};

#endif // CAPTURE_H
