#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


/*
 * This class is describe the data package infomation
 * +-----+------------+
 * | type| infomation |
 * +-----+------------+
 * |  1  |    arp     |
 * +-----+------------+
 * |  2  |    icmp    |
 * +-----+------------+
 * |  3  |    tcp     |
 * +-----+------------+
 * |  4  |    udp     |
 * +-----+------------+
 * |  5  |    dns     |
 * +-----+------------+
*/
class DataPackage
{
private:
    unsigned int data_length;
    QString timeStamp;
    QString info;
    int packageType;


protected:
    static QString byteToHex(u_char*str,int size);
public:
    // Construction
    DataPackage();
    ~DataPackage() = default;
    // set the var
    const u_char *pkt_content;
    void setDataLength(unsigned int length);
    void setTimeStamp(QString timeStamp);
    void setPackageType(int type);
    void setPackagePointer(const u_char *pkt_content,int size);
    void setPackageInfo(QString info);
    // get the var
    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();
    QString getSource();
    QString getDestination();
    // get the mac info
    QString getDesMacAddr();
    QString getSrcMacAddr();
    QString getMacType();
    // get the ip info
    QString getDesIpAddr();
    QString getSrcIpAddr();
    QString getIpVersion();
    QString getIpHeaderLength();
    QString getIpTos();
    QString getIpTotalLength();
    QString getIpIdentification();
    QString getIpFlag();
    QString getIpReservedBit();
    QString getIpDF();
    QString getIpMF();
    QString getIpFragmentOffset();
    QString getIpTTL();
    QString getIpProtocol();
    QString getIpCheckSum();
    // get the icmp info
    QString getIcmpType();
    QString getIcmpCode();
    QString getIcmpCheckSum();
    QString getIcmpIdentification();
    QString getIcmpSequeue();
    QString getIcmpData(int size);
    // get the arp info
    QString getArpHardwareType();
    QString getArpProtocolType();
    QString getArpHardwareLength();
    QString getArpProtocolLength();
    QString getArpOperationCode();
    QString getArpSourceEtherAddr();
    QString getArpSourceIpAddr();
    QString getArpDestinationEtherAddr();
    QString getArpDestinationIpAddr();
    // get the tcp info
    QString getTcpSourcePort();
    QString getTcpDestinationPort();
    QString getTcpSequence();
    QString getTcpAcknowledgment();
    QString getTcpHeaderLength();
    QString getTcpRawHeaderLength();
    QString getTcpFlags();
    QString getTcpPSH();
    QString getTcpACK();
    QString getTcpSYN();
    QString getTcpURG();
    QString getTcpFIN();
    QString getTcpRST();
    QString getTcpWindowSize();
    QString getTcpCheckSum();
    QString getTcpUrgentPointer();
    QString getTcpOperationKind(int kind);
    int getTcpOperationRawKind(int offset);
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5;
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    // get the udp info
    QString getUdpSourcePort();
    QString getUdpDestinationPort();
    QString getUdpDataLength();
    QString getUdpCheckSum();
    // get the dns info
    QString getDnsTransactionId();
    QString getDnsFlags();
    QString getDnsFlagsQR();
    QString getDnsFlagsOpcode();
    QString getDnsFlagsAA();
    QString getDnsFlagsTC();
    QString getDnsFlagsRD();
    QString getDnsFlagsRA();
    QString getDnsFlagsZ();
    QString getDnsFlagsRcode();
    QString getDnsQuestionNumber();
    QString getDnsAnswerNumber();
    QString getDnsAuthorityNumber();
    QString getDnsAdditionalNumber();
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);
};

#endif // DATAPACKAGE_H
