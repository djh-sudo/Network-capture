#include "datapackage.h"
#include <QMetaType>
#include "winsock.h"
#include <QVector>

DataPackage::DataPackage()
{
    // register the DataPackage type then
    qRegisterMetaType<DataPackage>("DataPackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->packageType = 0;
}

void DataPackage::setDataLength(unsigned int length){
    this->data_length = length;
}

void DataPackage::setTimeStamp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void DataPackage::setPackageType(int type){
    this->packageType = type;
}

void DataPackage::setPackagePointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    memcpy((char*)(this->pkt_content),pkt_content,size);
    //    this->pkt_content = pkt_content;
}
void DataPackage::setPackageInfo(QString info){
    this->info = info;
}
QString DataPackage::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i]>>4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

QString DataPackage::getTimeStamp(){
    return this->timeStamp;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getPackageType(){
    switch (this->packageType) {
    case 1:return "ARP";
    case 2:return "ICMP";
    case 3:return "TCP";
    case 4:return "UDP";
    case 5:return "DNS";
    default:{
        return "";
    }
    }
}

QString DataPackage::getInfo(){
    return info;
}

QString DataPackage::getSource(){
    if(this->packageType == 1)
        return getArpSourceIpAddr();
    else return getSrcIpAddr();
}
QString DataPackage::getDestination(){
    if(this->packageType == 1)
        return getArpDestinationIpAddr();
    else return getDesIpAddr();
}
/* Ether */
/********************** get destination ethenet address **********************/
QString DataPackage::getDesMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_char*addr;
    if(ethernet){
        addr = ethernet->ether_des_host;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get source ethenet address **********************/
QString DataPackage::getSrcMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_char*addr;
    if(ethernet){
        addr = ethernet->ether_src_host;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get ethenet type **********************/
QString DataPackage::getMacType(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_short ethernet_type = ntohs(ethernet->ether_type);
    switch (ethernet_type) {
    case 0x0800: return "IPv4(0x800)";
    case 0x0806:return "ARP(0x0806)";
    default:{
        return "";
    }
    }
}

/* ip */
/********************** get destination ip address **********************/
QString DataPackage::getDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}
/********************** get source ip address **********************/
QString DataPackage::getSrcIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}
/********************** get ip version **********************/
QString DataPackage::getIpVersion(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->versiosn_head_length >> 4);
}
/********************** get ip header length **********************/
QString DataPackage::getIpHeaderLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    QString res = "";
    int length = ip->versiosn_head_length & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}

/********************** get ip TOS **********************/
QString DataPackage::getIpTos(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->TOS));
}
/********************** get ip total length **********************/
QString DataPackage::getIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}
/********************** get ip indentification **********************/
QString DataPackage::getIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}
/********************** get ip flag **********************/
QString DataPackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}
/********************** get ip reverse bit **********************/
QString DataPackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString DataPackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString DataPackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}
/********************** get ip Fragment Offset **********************/
QString DataPackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}
/********************** get ip TTL **********************/
QString DataPackage::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}
/********************** get ip protocol **********************/
QString DataPackage::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}
/********************** get ip checksum **********************/
QString DataPackage::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

/* icmp */
/********************** get icmp type **********************/
QString DataPackage::getIcmpType(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->type));
}
/********************** get icmp code **********************/
QString DataPackage::getIcmpCode(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->code));

}
/********************** get icmp checksum **********************/
QString DataPackage::getIcmpCheckSum(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}
/********************** get icmp identification **********************/
QString DataPackage::getIcmpIdentification(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}
/********************** get icmp sequence **********************/
QString DataPackage::getIcmpSequeue(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->sequence));
}
QString DataPackage::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}
/* arp info */
QString DataPackage::getArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}
/********************** get arp protocol type **********************/
QString DataPackage::getArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}
/********************** get hardware length **********************/
QString DataPackage::getArpHardwareLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}
/********************** get arp protocol length **********************/
QString DataPackage::getArpProtocolLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->ip_length);
}
/********************** get arp operator code **********************/
QString DataPackage::getArpOperationCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}
/********************** get arp source ethernet address **********************/
QString DataPackage::getArpSourceEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->src_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp destination ethernet address **********************/
QString DataPackage::getArpDestinationEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->des_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp source ip address **********************/
QString DataPackage::getArpSourceIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return srcIp;
    }
    return "";
}
/********************** get arp destination ip address **********************/
QString DataPackage::getArpDestinationIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}

/* tcp */
/********************** get tcp source port **********************/
QString DataPackage::getTcpSourcePort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->src_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp destination port **********************/
QString DataPackage::getTcpDestinationPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->des_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp sequence **********************/
QString DataPackage::getTcpSequence(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->sequence));
}
/********************** get tcp acknowledgment **********************/
QString DataPackage::getTcpAcknowledgment(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->ack));
}
/********************** get tcp header length **********************/
QString DataPackage::getTcpHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int length = (tcp->header_length >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}
QString DataPackage::getTcpRawHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->header_length >> 4);
}

/********************** get tcp flags **********************/
QString DataPackage::getTcpFlags(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);
}

/********************** get tcp PSH **********************/
QString DataPackage::getTcpPSH(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}
/********************** get tcp ACK **********************/
QString DataPackage::getTcpACK(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}
/********************** get tcp SYN **********************/
QString DataPackage::getTcpSYN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}
/********************** get tcp UGR **********************/
QString DataPackage::getTcpURG(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}
/********************** get tcp FIN **********************/
QString DataPackage::getTcpFIN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}
/********************** get tcp RST **********************/
QString DataPackage::getTcpRST(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}
/********************** get tcp window size **********************/
QString DataPackage::getTcpWindowSize(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->window_size));
}
/********************** get tcp checksum **********************/
QString DataPackage::getTcpCheckSum(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}
/********************** get tcp urgent pointer **********************/
QString DataPackage::getTcpUrgentPointer(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->urgent));
}

QString DataPackage::getTcpOperationKind(int kind){
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}
int DataPackage::getTcpOperationRawKind(int offset){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    return *tcp;
}
bool DataPackage::getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 5){
        tcp++;
        length = *tcp;
        tcp++;
        u_int* pointer = (u_int*)tcp;
        for(int i = 0;i < (length - 2)/4;i++){
            u_int temp = htonl(*pointer);
            edge.push_back(temp);
            pointer++;
        }
        return true;
    }else return false;
}
bool DataPackage::getTcpOperationMSS(int offset, u_short &mss){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 2){
        tcp++;
        if(*tcp == 4){
            tcp++;
            u_short* Mss = (u_short*)tcp;
            mss = ntohs(*Mss);
            return true;
        }
        else return false;
    }
    return false;
}
bool DataPackage::getTcpOperationSACKP(int offset){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 4)
        return true;
    else return false;
}
bool DataPackage::getTcpOperationWSOPT(int offset, u_char &shit){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 3){
        tcp++;
        if(*tcp == 3){
            tcp++;
            shit = *tcp;
        }else return false;
    }else return false;
}

bool DataPackage::getTcpOperationTSPOT(int offset, u_int &value, u_int &reply){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 8){
        tcp++;
        if(*tcp == 10){
            tcp++;
            u_int *pointer = (u_int*)(tcp);
            value = ntohl(*pointer);
            pointer++;
            reply = ntohl(*pointer);
            return true;
        }else return false;
    }else return false;
}
/* udp */
/********************** get udp source port **********************/
QString DataPackage::getUdpSourcePort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->src_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp destination port **********************/
QString DataPackage::getUdpDestinationPort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->des_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp data length **********************/
QString DataPackage::getUdpDataLength(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->data_length));

}
/********************** get udp checksum **********************/
QString DataPackage::getUdpCheckSum(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->checksum),16);
}

/* dns */
/********************** get dns transaction **********************/
QString DataPackage::getDnsTransactionId(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->identification),16);
}
/********************** get dns flag **********************/
QString DataPackage::getDnsFlags(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    int type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "(Standard query)";
    }
    else if((type & 0xf800) == 0x8000){
        info = "(Standard query response)";
    }
    return QString::number(type,16) + info;
}
/********************** get dns QR **********************/
QString DataPackage::getDnsFlagsQR(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x8000) >> 15);
}
/********************** get dns Operation code **********************/
QString DataPackage::getDnsFlagsOpcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x7800) >> 11);
}
/********************** get dns AA **********************/
QString DataPackage::getDnsFlagsAA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0400) >> 10);
}
/********************** get dns TC **********************/
QString DataPackage::getDnsFlagsTC(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0200) >> 9);
}
/********************** get dns RD **********************/
QString DataPackage::getDnsFlagsRD(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0100) >> 8);
}
/********************** get dns RA **********************/
QString DataPackage::getDnsFlagsRA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0080) >> 7);
}
/********************** get dns Z(reserved) **********************/
QString DataPackage::getDnsFlagsZ(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0070) >> 4);
}
/********************** get dns Response code **********************/
QString DataPackage::getDnsFlagsRcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x000f));
}
/********************** get dns Question number **********************/
QString DataPackage::getDnsQuestionNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->question));
}
/********************** get dns Answer number **********************/
QString DataPackage::getDnsAnswerNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->answer));
}
/********************** get dns Authority number **********************/
QString DataPackage::getDnsAuthorityNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->authority));
}
/********************** get dns Additional number **********************/
QString DataPackage::getDnsAdditionalNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->additional));
}
/********************** get dns query result **********************/
void DataPackage::getDnsQueriesDomain(QString&name,int&Type,int&Class){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    domain++;
    name = name.left(name.length() - 1);
    DNS_QUESITON *qus = (DNS_QUESITON*)(domain);
    Type = ntohs(qus->query_type);
    Class = ntohs(qus->query_class);
}
/********************** get dns domian name **********************/
QString DataPackage::getDnsDomainName(int offset){
    char*dns;
    dns = (char*)(pkt_content + 14 + 20 + 8 + offset);
    QString name = "";
    while(dns && *dns != 0x00){
        if((unsigned char)(*dns) <= 64){
            int length = *dns;
            dns++;
            for(int k = 0;k<length;k++){
                name += (*dns);
                dns++;
            }
            name += ".";
        }else if(((*dns) & 0xc0) == 0xc0){
            int accOffset = (((*dns) & 0x3f) << 8);
            dns++;
            accOffset += (unsigned char)(*dns);
            name += getDnsDomainName(accOffset) + ".";
            dns++;
            break;
        }
    }
    name = name.left(name.length() - 1);
    return name;
}
/********************** get dns answer result **********************/
int DataPackage::getDnsAnswersDomain(int offset, QString &name1, u_short &Type, u_short &Class, u_int &ttl, u_short &dataLength,QString&name2){
    char*dns = (char*)(pkt_content + 14 + 20 + 8 + 12 + offset);
    if(((*dns) & 0xc0) == 0xc0){
        int accOffset = (((*dns) & 0x3f) << 8);
        dns++; //
        accOffset += (*dns);
        name1 = getDnsDomainName(accOffset);
        dns++; //
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        dns += (2 + 2 + 4 + 2);
        if(dataLength == 4){
            for(int i = 0;i < 4;i++){
                name2 += QString::number((unsigned char)(*dns));
                name2 += ".";
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (unsigned char)(*dns);
                    name2 += getDnsDomainName(accOffset) + ".";
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2;

    }else{
        name1 = getDnsDomainName(offset + 12);
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns + name1.size() + 2);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        if(dataLength == 4){
            dns += (2 + 2 + 4 + 2 + name1.size() + 1);
            for(int i = 0;i < 4;i++){
                name2 += (unsigned char)(*dns);
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (*dns);
                    name2 += getDnsDomainName(accOffset);
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
    }
}
/********************** get dns domain type **********************/
QString DataPackage::getDnsDomainType(int type){
    switch (type) {
    case 1: return "A (Host Address)";
    case 2:return "NS";
    case 5:return "CNAME (Canonical NAME for an alias)";
    case 6:return "SOA";
    case 11:return "WSK";
    case 12:return "PTR";
    case 13:return "HINFO";
    case 15:return "MX";
    case 28:return "AAAA";
    case 252:return "AXFR";
    case 255:return "ANY";
    default:return "";
    }
}
