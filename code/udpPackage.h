#ifndef UDPPACKAGE_H
#define UDPPACKAGE_H

#include <QString>

typedef struct udp{
    QString srcEthernetAddr;
    QString desEthernetAddr;
    QString EthernetType;
    //
    QString srcIpAddr;
    QString desIpAddr;
    QString ipVersion;
    QString ipHeaderLength;
    QString IpTos;
    QString totalLength;
    QString ipIdentification;
    QString ipFlag;
    QString ipReverseBit;
    QString ipDF;
    QString ipMF;
    QString ipFragmentOffset;
    QString ipTTL;
    QString ipProtocol;
    QString ipCheckSum;
    //
    QString udpSrcPort;
    QString udpDesPort;
    QString dataLength;
    QString udpCheckSum;
}UDP;

#endif // UDPPACKAGE_H
