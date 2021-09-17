#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include <QDebug>
#include "winsock2.h"
#include "capture.h"
#include <QStringList>
#include <QColor>
#include <QMessageBox>
#include <QTreeWidgetItem>
#include <QStringList>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome to shark!");
    ui->toolBar->addAction(ui->actionstart_capture);
    ui->toolBar->addAction(ui->actionclear_all);
    ui->toolBar->addAction(ui->actionup);
    ui->toolBar->addAction(ui->actiondown);
    ui->toolBar->addAction(ui->actionTop);
    ui->toolBar->addAction(ui->actionEnd);

    showNetworkCard();
    Capture *thread = new Capture;
    ui->comboBox->setEnabled(true);
    isStart = false;
    static bool index = false;
    countNumber = 0;
    rowNumber = -1;
    data.clear();
    device = nullptr;
    pointer = nullptr;
    connect(ui->actionstart_capture,&QAction::triggered,this,[=]{
        index = !index;
        if(index){
            if(ui->tableWidget->rowCount()){
                int type = QMessageBox::information(NULL,"information","Before restarting do you want to save result?","Save","Continue","Cancel");
                if(type == 0)
                {
                    // save the file...
                }else if(type == 1){
                    qDebug()<<"not save";
                }else{
                    index = !index;
                    isStart = false;
                    return;
                }
            }
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            ui->treeWidget->clear();
            countNumber = 0;
            rowNumber = -1;
            int dataSize = this->data.size();
            for(int i = 0;i < dataSize;i++){
                free((char*)(this->data[i].pkt_content));
                this->data[i].pkt_content = nullptr;
            }
            QVector<DataPackage>().swap(data);
            int res = capture();
            if(pointer && res != -1){
                thread->resetFlag();
                thread->setPointer(pointer);
                ui->comboBox->setEnabled(false);
                thread->start();
                ui->actionstart_capture->setIcon(QIcon(":/stop.png"));
                countNumber = 0;
                isStart = true;
            }else{ // fail to start
                index = !index;
                countNumber = 0;
                rowNumber = -1;
                isStart = false;
            }
        }else{
            thread->setFlag();
            ui->comboBox->setEnabled(true);
            thread->quit();
            thread->wait();
            pcap_close(pointer);
            ui->actionstart_capture->setIcon(QIcon(":/start.png"));
            isStart = false;
        }
    });

    connect(ui->actionclear_all,&QAction::triggered,this,[=]{
        if(!isStart){
            int type = QMessageBox::information(this,"information","Do you want to clear all?","Yes","Cancel");
            if(type == 0){
                ui->tableWidget->clearContents();
                ui->tableWidget->setRowCount(0);
                ui->treeWidget->clear();
                countNumber = 0;
                rowNumber = -1;
                int dataSize = this->data.size();
                for(int i = 0;i < dataSize;i++){
                    free((char*)(this->data[i].pkt_content));
                    this->data[i].pkt_content = nullptr;
                }
                QVector<DataPackage>().swap(data);
            }else return;
        }
    });

    connect(ui->actionup,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(index - 1,0);
            on_tableWidget_cellClicked(index - 1,0);
        }else return;
    });

    connect(ui->actiondown,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index >= 0 && index < ui->tableWidget->rowCount() - 1){
            ui->tableWidget->setCurrentCell(index + 1,0);
            on_tableWidget_cellClicked(index + 1,0);
        }else return;
    });

    connect(ui->actionTop,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(0,0);
            on_tableWidget_cellClicked(0,0);
        }else return;
    });

    connect(ui->actionEnd,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->rowCount() - 1;
        if(index > 0){
            ui->tableWidget->setCurrentCell(index,0);
            on_tableWidget_cellClicked(index,0);
        }
    });

    connect(thread,&Capture::send,this,&MainWindow::handleMessage);


    ui->tableWidget->setShowGrid(false);
    ui->toolBar->setMovable(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnCount(7);
    readOnlyDelegate = new ReadOnlyDelegate();
    ui->tableWidget->setItemDelegate(readOnlyDelegate);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);
}

MainWindow::~MainWindow()
{
    int dataSize = this->data.size();
    for(int i = 0;i<dataSize;i++){
        free((char*)(this->data[i].pkt_content));
        this->data[i].pkt_content = nullptr;
    }
    QVector<DataPackage>().swap(data);
    delete readOnlyDelegate;
    delete ui;
}

void MainWindow::showNetworkCard(){
    int n = pcap_findalldevs(&all_devices,errbuf);
    ui->comboBox->clear();
    if(n == -1){
        statusBar()->showMessage("There is something wrong" + QString(errbuf));
        ui->comboBox->addItem("Cannot find a matching network card, please restart and test");
        return;
    }
    ui->comboBox->clear();
    ui->comboBox->addItem("please chose the Network Card!");
    for(device = all_devices;device!= nullptr;device = device->next){
        QString device_name = device->name;
        device_name.replace("\\Device\\","");
        QString device_description = device->description;
        QString item = device_name + "   " + device_description;
        ui->comboBox->addItem(item);
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index!=0){
        for(device = all_devices;i<index - 1;i++,device = device->next);
    }
    return;
}

int MainWindow::capture(){
    // pcap_t * pcap_open_live(char*device,int snaplen,int promisc,int to_ms,char*errbuf);
    if(device)
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    else{
        statusBar()->showMessage("pls choose Network Card!");
        return -1;
    }
    if(!pointer){
        statusBar()->showMessage(errbuf);
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    }else{
        // check the data link IEEE 802.3
        if(pcap_datalink(pointer)!=DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}

void MainWindow::handleMessage(DataPackage data){
    ui->tableWidget->insertRow(countNumber);
    this->data.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "TCP"){
        color = QColor(216,191,216);
    }else if(type == "ICMP"){
        color = QColor(144,238,144);
    }
    else if(type == "ARP"){
        color = QColor(238,238,0);
    }
    else if(type == "DNS"){
        color = QColor(255,255,224);
    }else if(type == "SSL"){
        color = QColor(210,130,210);
    }else{
        color = QColor(255,218,185);
    }
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(rowNumber == row || row < 0){
        return;
    }else{
        ui->treeWidget->clear();
        rowNumber = row;
        if(rowNumber < 0 || rowNumber > data.size())
            return;
        QString desMac = data[rowNumber].getDesMacAddr();
        QString srcMac = data[rowNumber].getSrcMacAddr();
        QString type = data[rowNumber].getMacType();
        QString tree1 = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree1);
        ui->treeWidget->addTopLevelItem(item);

        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

        QString packageType = data[rowNumber].getPackageType();
        if(packageType == "ARP"){
            QString ArpType = data[rowNumber].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
            ui->treeWidget->addTopLevelItem(item2);
            QString HardwareType = data[rowNumber].getArpHardwareType();
            QString protocolType = data[rowNumber].getArpProtocolType();
            QString HardwareSize = data[rowNumber].getArpHardwareLength();
            QString protocolSize = data[rowNumber].getArpProtocolLength();
            QString srcMacAddr = data[rowNumber].getArpSourceEtherAddr();
            QString desMacAddr = data[rowNumber].getArpDestinationEtherAddr();
            QString srcIpAddr = data[rowNumber].getArpSourceIpAddr();
            QString desIpAddr = data[rowNumber].getArpDestinationIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:" + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:" + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:" + HardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:" + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:" + ArpType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:" + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:" + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:" + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:" + desIpAddr));
            return;
        }else { // ip
            QString srcIp = data[rowNumber].getSrcIpAddr();
            QString desIp = data[rowNumber].getDesIpAddr();

            QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
            ui->treeWidget->addTopLevelItem(item3);

            QString version = data[rowNumber].getIpVersion();
            QString headerLength = data[rowNumber].getIpHeaderLength();
            QString Tos = data[rowNumber].getIpTos();
            QString totalLength = data[rowNumber].getIpTotalLength();
            QString id = "0x" + data[rowNumber].getIpIdentification();
            QString flags = data[rowNumber].getIpFlag();
            if(flags.size()<2)
                flags = "0" + flags;
            flags = "0x" + flags;
            QString FragmentOffset = data[rowNumber].getIpFragmentOffset();
            QString ttl = data[rowNumber].getIpTTL();
            QString protocol = data[rowNumber].getIpProtocol();
            QString checksum = "0x" + data[rowNumber].getIpCheckSum();
            int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
            item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

            QString reservedBit = data[rowNumber].getIpReservedBit();
            QString DF = data[rowNumber].getIpDF();
            QString MF = data[rowNumber].getIpMF();
            QString FLAG = ",";

            if(reservedBit == "1"){
                FLAG += "Reserved bit";
            }
            else if(DF == "1"){
                FLAG += "Don't fragment";
            }
            else if(MF == "1"){
                FLAG += "More fragment";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
            item3->addChild(bitTree);
            QString temp = reservedBit == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
            temp = DF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
            temp = MF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

            item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));

            if(packageType == "TCP"){
                QString desPort = data[rowNumber].getTcpDestinationPort();
                QString srcPort = data[rowNumber].getTcpSourcePort();
                QString ack = data[rowNumber].getTcpAcknowledgment();
                QString seq = data[rowNumber].getTcpSequence();
                QString headerLength = data[rowNumber].getTcpHeaderLength();
                int length = data[rowNumber].getTcpRawHeaderLength().toUtf8().toInt();
                dataLengthofIp -= (length * 4);
                QString dataLength = QString::number(dataLengthofIp);
                QString flag = data[rowNumber].getTcpFlags();
                while(flag.size()<2)
                    flag = "0" + flag;
                flag = "0x" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

                ui->treeWidget->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number:" + ack));

                QString sLength = QString::number(length,2);
                while(sLength.size()<4)
                    sLength = "0" + sLength;
                item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

                QString PSH = data[rowNumber].getTcpPSH();
                QString URG = data[rowNumber].getTcpURG();
                QString ACK = data[rowNumber].getTcpACK();
                QString RST = data[rowNumber].getTcpRST();
                QString SYN = data[rowNumber].getTcpSYN();
                QString FIN = data[rowNumber].getTcpFIN();
                QString FLAG = "";

                if(PSH == "1")
                    FLAG += "PSH,";
                if(URG == "1")
                    FLAG += "UGR,";
                if(ACK == "1")
                    FLAG += "ACK,";
                if(RST == "1")
                    FLAG += "RST,";
                if(SYN == "1")
                    FLAG += "SYN,";
                if(FIN == "1")
                    FLAG += "FIN,";
                FLAG = FLAG.left(FLAG.length()-1);
                QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
                item4->addChild(flagTree);
                QString temp = URG == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
                temp = ACK == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
                temp = PSH == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
                temp = RST == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
                temp = SYN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
                temp = FIN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

                QString window = data[rowNumber].getTcpWindowSize();
                QString checksum = "0x" + data[rowNumber].getTcpCheckSum();
                QString urgent = data[rowNumber].getTcpUrgentPointer();
                item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
                if((length * 4) > 20){
                    QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(length * 4 - 20) + ") bytes");
                    item4->addChild(optionTree);
                    for(int j = 0;j < (length * 4 - 20);){
                        int kind = data[rowNumber].getTcpOperationRawKind(j);
                        switch (kind) {
                        case 0:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - End of List (EOL)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind:End of List (0)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }case 1:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - No-Operation (NOP)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: No-Operation (1)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }
                        case 2:{
                            u_short mss;
                            if(data[rowNumber].getTcpOperationMSS(j,mss)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Maximun Segment Size: " + QString::number(mss) + " bytes");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Maximun Segment Size (2)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: " + QString::number(mss)));
                                j += 4;
                            }
                            break;
                        }
                        case 3:{
                            u_char shift;
                            if(data[rowNumber].getTcpOperationWSOPT(j,shift)){
                                int factor = 1 << shift;
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Window scale: " + QString::number(shift) + " (multiply by " + QString::number(factor) + ")");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Window scale (3)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 3"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Shift Count: " + QString::number(shift)));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"[Multiplier: " + QString::number(factor) + "]"));
                                j += 3;
                            }
                            break;
                        }
                        case 4:{
                            if(data[rowNumber].getTcpOperationSACKP(j)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK Permitted");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK Permitted (4)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 2"));
                                j += 2;
                            }
                            break;
                        }
                        case 5:{
                            u_char length = 0;
                            QVector<u_int>edge;
                            if(data[rowNumber].getTcpOperationSACK(j,length,edge)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK (5)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(length)));
                                int num = edge.size();
                                for(int k = 0;k < num;k += 2){
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"left edge = " + QString::number(edge[k])));
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"right edge = " + QString::number(edge[k + 1])));
                                }
                                j += length;
                            }
                            break;
                        }
                        case 8:{
                            u_int value = 0;
                            u_int reply = 0;
                            if(data[rowNumber].getTcpOperationTSPOT(j,value,reply)){
                                QString val = QString::number(value);
                                QString rep = QString::number(reply);
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - TimeStamps: TSval " +val + ", TSecr " + rep);
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: Time Stamp Option (8)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 10"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp value: " + val));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp echo reply: " + rep));
                                j += 10;
                            }
                            break;
                        }
                        case 19:{
                            j += 18;
                            break;
                        }
                        case 28:{
                            j += 4;
                            break;
                        }
                        default:{
                            j++;
                            break;
                        }
                        }
                    }
                }
                if(dataLengthofIp > 0){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload (" + QString::number(dataLengthofIp) + ")"));
                }
            }else if(packageType == "UDP" || packageType == "DNS"){
                QString srcPort = data[rowNumber].getUdpSourcePort();
                QString desPort = data[rowNumber].getUdpDestinationPort();
                QString Length = data[rowNumber].getUdpDataLength();
                QString checksum = "0x" + data[rowNumber].getUdpCheckSum();
                QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
                ui->treeWidget->addTopLevelItem(item5);
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                int udpLength = Length.toUtf8().toInt();
                if(udpLength > 0){
                    item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
                }
                if(packageType == "DNS"){
                    QString transaction = "0x" + data[rowNumber].getDnsTransactionId();
                    QString QR = data[rowNumber].getDnsFlagsQR();
                    QString temp = "";
                    if(QR == "0") temp = "query";
                    if(QR == "1") temp = "response";
                    QString flags = "0x" + data[rowNumber].getDnsFlags();
                    QTreeWidgetItem*dnsTree = new QTreeWidgetItem(QStringList()<<"Domain Name System (" + temp + ")");
                    ui->treeWidget->addTopLevelItem(dnsTree);
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID:" + transaction));
                    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags);
                    dnsTree->addChild(flagTree);
                    temp = QR == "1"?"Message is a response":"Message is a query";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<QR + "... .... .... .... = Response:" + temp));
                    QString Opcode = data[rowNumber].getDnsFlagsOpcode();
                    if(Opcode == "0") temp = "Standard query (0)";
                    else if(Opcode == "1") temp = "Reverse query (1)";
                    else if(Opcode == "2") temp = "Status request (2)";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".000 " + Opcode + "... .... .... = Opcode:" + temp));
                    if(QR == "1"){
                        QString AA = data[rowNumber].getDnsFlagsAA();
                        temp = AA == "1"?"Server is an authority for domain":"Server is not an authority for domain";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ." + AA + ".. .... .... = Authoritative:" + temp));
                    }
                    QString TC = data[rowNumber].getDnsFlagsTC();
                    temp = TC == "1"?"Message is truncated":"Message is not truncated";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + TC + ". .... .... = Truncated:" + temp));

                    QString RD = data[rowNumber].getDnsFlagsRD();
                    temp = RD == "1"?"Do query recursively":"Do query not recursively";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + RD + " .... .... = Recursion desired:" + temp));

                    if(QR == "1"){
                        QString RA = data[rowNumber].getDnsFlagsRA();
                        temp = RA == "1"?"Server can do recursive queries":"Server can not do recursive queries";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + RA + "... .... = Recursion available:" + temp));
                    }
                    QString Z = data[rowNumber].getDnsFlagsZ();
                    while(Z.size()<3)
                        Z = "0" + Z;
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + Z + " .... = Z:reserved(" + Z + ")"));
                    if(QR == "1"){
                        QString Rcode = data[rowNumber].getDnsFlagsRcode();
                        if(Rcode == "0")
                            temp = "No error (0)";
                        else if(Rcode == "1") temp = "Format error (1)";
                        else if(Rcode == "2") temp = "Server failure (2)";
                        else if(Rcode == "3") temp = "Name Error (3)";
                        else if(Rcode == "4") temp = "Not Implemented (4)";
                        else if(Rcode == "5") temp = "Refused (5)";
                        int code = Rcode.toUtf8().toInt();
                        QString bCode = QString::number(code,2);
                        while (bCode.size()<4)
                            bCode = "0" + bCode;
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .... " + bCode + " = Reply code:" + temp));
                    }

                    QString question = data[rowNumber].getDnsQuestionNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Questions:" + question));
                    QString answer = data[rowNumber].getDnsAnswerNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs:" + answer));
                    QString authority = data[rowNumber].getDnsAuthorityNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs:" + authority));
                    QString additional = data[rowNumber].getDnsAdditionalNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Additional RRs:" + additional));
                    int offset = 0;
                    if(question == "1"){
                        QString domainInfo;
                        int Type;
                        int Class;
                        data[rowNumber].getDnsQueriesDomain(domainInfo,Type,Class);
                        QTreeWidgetItem*queryDomainTree = new QTreeWidgetItem(QStringList()<<"Queries");
                        dnsTree->addChild(queryDomainTree);
                        offset += (4 + domainInfo.size() + 2);
                        QString type = data[rowNumber].getDnsDomainType(Type);
                        QTreeWidgetItem*querySubTree = new QTreeWidgetItem(QStringList()<<domainInfo + " type " + type + ", class IN");
                        queryDomainTree->addChild(querySubTree);
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + domainInfo));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"[Name Length:" + QString::number(domainInfo.size()) + "]"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type + "(" + QString::number(Type) + ")"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                    }
                    int answerNumber = answer.toUtf8().toInt();
                    if(answerNumber > 0){
                        QTreeWidgetItem*answerTree = new QTreeWidgetItem(QStringList()<<"Answers");
                        dnsTree->addChild(answerTree);
                        for(int i = 0;i< answerNumber;i++){
                            QString name1;
                            QString name2;
                            u_short type;
                            u_short Class;
                            u_int ttl;
                            u_short length;

                            int tempOffset = data[rowNumber].getDnsAnswersDomain(offset,name1,type,Class,ttl,length,name2);
                            QString sType = data[rowNumber].getDnsDomainType(type);
                            QString temp = "";
                            if(type == 1) temp = "addr";
                            else if(type == 5) temp = "cname";
                            QTreeWidgetItem*answerSubTree = new QTreeWidgetItem(QStringList()<<name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
                            answerTree->addChild(answerSubTree);
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + name1));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + sType + "(" + QString::number(type) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Data length:" + QString::number(length)));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<sType + ":" + name2));

                            offset += tempOffset;
                        }
                    }
                }

            }else if(packageType == "ICMP"){
                dataLengthofIp -= 8;
                QTreeWidgetItem*item6 = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
                ui->treeWidget->addTopLevelItem(item6);
                QString type = data[rowNumber].getIcmpType();
                QString code = data[rowNumber].getIcmpCode();
                QString info = ui->tableWidget->item(row,6)->text();
                QString checksum = "0x" + data[rowNumber].getIcmpCheckSum();
                QString id = data[rowNumber].getIcmpIdentification();
                QString seq = data[rowNumber].getIcmpSequeue();
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
                if(dataLengthofIp > 0){
                    QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
                    item6->addChild(dataItem);
                    QString icmpData = data[rowNumber].getIcmpData(dataLengthofIp);
                    dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
                }
            }
        }
        int macDataLength = data[rowNumber].getIpTotalLength().toUtf8().toInt();
        int dataPackageLength = data[rowNumber].getDataLength().toUtf8().toInt();
        int delta = dataPackageLength - macDataLength;
        if(delta > 14){
            int padding = delta - 14;
            QString pad = "";
            while (pad.size() < padding * 2) {
                pad += "00";
            }
            item->addChild(new QTreeWidgetItem(QStringList()<<"Padding: " + pad));
        }
    }
}
// enterKey pressed will emit event
void MainWindow::on_lineEdit_returnPressed()
{
    QString text = ui->lineEdit->text();
    text = text.toUpper();
    QString target = "#";
    if(text == "" || text == "UDP" || text == "TCP" || text == "DNS" || text == "ARP"|| text == "ICMP"){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
        target = text;
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
    int count = 0;
    int number = ui->tableWidget->rowCount();
    if(!isStart && target != "#"){
        if(target!=""){
            for(int i = 0;i < number;i++){
                if(ui->tableWidget->item(i,4)->text() != target){
                    ui->tableWidget->setRowHidden(i,true);
                }else{
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
        }else{
            int number = ui->tableWidget->rowCount();
            for(int i = 0;i < number;i++){
                ui->tableWidget->setRowHidden(i,false);
                count++;
            }
        }
    }

    double res = 0;
    if(number != 0)
        res = (count*100.0)/number;
    statusBar()->showMessage("Have show (" + QString::number(count) + ") " +QString::number(res,10,2) + "%");
}
// lineEdit text change will emit event
void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    QString text = arg1;
    text = text.toLower();
    if(text == "" || text == "udp" || text == "tcp" || text == "dns" || text == "arp" || text == "icmp"){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
}
// tablewidget item change will emit the event
void MainWindow::on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn)
{
    if((currentRow != previousRow) && previousRow >= 0){
        on_tableWidget_cellClicked(currentRow,currentColumn);
    }else return;
}
