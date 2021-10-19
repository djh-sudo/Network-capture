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

/*
 * MainWindow
 * Constructure function
 * initialize the variables and GUI
*/
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome to shark!");
    // set the toolbar
    ui->toolBar->addAction(ui->actionstart_capture);
    ui->toolBar->addAction(ui->actionclear_all);
    ui->toolBar->addAction(ui->actionup);
    ui->toolBar->addAction(ui->actiondown);
    ui->toolBar->addAction(ui->actionTop);
    ui->toolBar->addAction(ui->actionEnd);
    // show network card
    showNetworkCard();
    // initialization
    Capture *thread = new Capture;
    ui->comboBox->setEnabled(true);
    isStart = false;
    static bool index = false;
    countNumber = 0;
    rowNumber = -1;
    data.clear();
    device = nullptr;
    pointer = nullptr;

    // add the signal-slot
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

    // initialization
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

/*
 * ~MainWindow
 * Destructure function
 * free memory
*/
MainWindow::~MainWindow()
{
    // free the memory you have allocated!
    int dataSize = this->data.size();
    for(int i = 0;i<dataSize;i++){
        free((char*)(this->data[i].pkt_content));
        this->data[i].pkt_content = nullptr;
    }
    // do not use 'data.clear()' only,it can't free totally!
    QVector<DataPackage>().swap(data);
    delete readOnlyDelegate;
    delete ui;
}

/*
 * showNetworkCard
 * scan the network cards and show information about it at combox
*/
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

/*
 * on_comboBox_currentIndexChanged
 * when item of combox changed,the device pointer will also change
 * this function could ensure device pointer point to the selected network card
*/
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index!=0){
        for(device = all_devices;i<index - 1;i++,device = device->next);
    }else{
        device = nullptr;
    }
    return;
}

/*
 * capture
 * starting capture the data package from card
 * the data package in data link layer must meet the IEEE 802.3 protocol
 * or it will be throwed away
*/
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
        if(pcap_datalink(pointer) != DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}

/*
 * handleMessage
 * slot function Auto trigger
 * This function will analysis package it received and show in the table
*/
void MainWindow::handleMessage(DataPackage data){
    ui->tableWidget->insertRow(countNumber);
    this->data.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    // show different color
    if(type == TCP){
        color = QColor(216,191,216);
    }else if(type == TCP){
        color = QColor(144,238,144);
    }
    else if(type == ARP){
        color = QColor(238,238,0);
    }
    else if(type == DNS){
        color = QColor(255,255,224);
    }else if(type == TLS || type == SSL){
        color = QColor(210,149,210);
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
    // set color
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}

/*
 * on_tableWidget_cellClicked
 * click the table item the detail inforamation will show at the bottom tree widget
 * this function will analysis data pakckage chosed in detail
*/
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
        // arp package analysis
        if(packageType == ARP){
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
        }else { // ip package analysis
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

            if(packageType == TCP || packageType == TLS || packageType == SSL){
                QString desPort = data[rowNumber].getTcpDestinationPort();
                QString srcPort = data[rowNumber].getTcpSourcePort();
                QString ack = data[rowNumber].getTcpAcknowledgment();
                QString seq = data[rowNumber].getTcpSequence();
                QString headerLength = data[rowNumber].getTcpHeaderLength();
                int rawLength = data[rowNumber].getTcpRawHeaderLength().toUtf8().toInt();
                dataLengthofIp -= (rawLength * 4);
                QString dataLength = QString::number(dataLengthofIp);
                QString flag = data[rowNumber].getTcpFlags();
                while(flag.size()<2)
                    flag = "0" + flag;
                flag = "0x" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

                ui->treeWidget->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


                QString sLength = QString::number(rawLength,2);
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
                if(SYN == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
                }
                if(SYN == "1" && ACK == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
                }
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
                if((rawLength * 4) > 20){
                    QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(rawLength * 4 - 20) + ") bytes");
                    item4->addChild(optionTree);
                    for(int j = 0;j < (rawLength * 4 - 20);){
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
                    if(packageType == TLS){
                        QTreeWidgetItem* tlsTree = new QTreeWidgetItem(QStringList()<<"Transport Layer Security");
                        ui->treeWidget->addTopLevelItem(tlsTree);
                        u_char contentType = 0;
                        u_short version = 0;
                        u_short length = 0;
                        data[rowNumber].getTlsBasicInfo((rawLength * 4),contentType,version,length);
                        QString type = data[rowNumber].getTlsContentType(contentType);
                        QString vs = data[rowNumber].getTlsVersion(version);
                        switch (contentType) {
                        case 20:{
                            // ... TODO
                            break;
                        }
                        case 21:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: Encrypted Alert");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Alert Message: Encrypted Alert"));
                            break;
                        }
                        case 22:{ // handshake
                            u_char handshakeType = 0;
                            data[rowNumber].getTlsHandshakeType((rawLength * 4 + 5),handshakeType);
                            if(handshakeType == 1){ // client hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipherLength = 0;
                                QVector<u_short>cipher;
                                u_char cmLength = 0;
                                QVector<u_char>compressionMethod;
                                u_short extensionLength = 0;
                                data[rowNumber].getTlsClientHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipherLength,cipher,cmLength,compressionMethod,extensionLength);

                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = data[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites Length: " + QString::number(cipherLength)));
                                if(cipherLength > 0){
                                    QTreeWidgetItem* cipherTree = new QTreeWidgetItem(QStringList()<<"Cipher Suites (" + QString::number(cipherLength/2) + " suites)");
                                    handshakeTree->addChild(cipherTree);
                                    for(int k = 0;k < cipherLength/2;k++){
                                        QString temp = data[rowNumber].getTlsHandshakeCipherSuites(cipher[k]);
                                        cipherTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suite: " + temp));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Method Length: " + QString::number(cmLength)));
                                if(cmLength > 0){
                                    QTreeWidgetItem* cmTree = new QTreeWidgetItem(QStringList()<<"Compression Methods (" + QString::number(cmLength) + " method)");
                                    handshakeTree->addChild(cmTree);
                                    for(int k = 0;k < cmLength;k++){
                                        QString temp = data[rowNumber].getTlsHandshakeCompression(compressionMethod[k]);
                                        cmTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod[k]) + ")"));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = data[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            data[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            data[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            data[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            data[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            data[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            data[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            data[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = data[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = data[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            data[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = data[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            data[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }
                            }
                            else if(handshakeType == 2){// Server hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipher = 0;
                                u_char compressionMethod = 0;
                                u_short extensionLength = 0;
                                data[rowNumber].getTlsServerHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipher,compressionMethod,extensionLength);
                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = data[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion,16) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                QString temp = data[rowNumber].getTlsHandshakeCipherSuites(cipher);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites: " +temp));
                                temp = data[rowNumber].getTlsHandshakeCompression(compressionMethod);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = data[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            data[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            data[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            data[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            data[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            data[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            data[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            data[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = data[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = data[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            data[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = data[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            data[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }

                            }
                            else if(handshakeType == 12){// Server Key Exchange
                                int tlsLength = 0;
                                u_char curveType = 0;
                                u_short curveName = 0;
                                u_char pubLength = 0;
                                QString pubKey = "";
                                u_short sigAlgorithm = 0;
                                u_short sigLength = 0;
                                QString sig = "";
                                data[rowNumber].getTlsServerKeyExchange((rawLength * 4 + 5),handshakeType,tlsLength,curveType,curveName,pubLength,pubKey,sigAlgorithm,sigLength,sig);
                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                            }
                            // ... TODO
                            break;
                        }
                        case 23:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: http-over-tls");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Encrypted Application Data: ..."));
                            break;
                        }
                        default:break;
                        }
                    }else if(packageType == SSL){
                        ui->treeWidget->addTopLevelItem(new QTreeWidgetItem(QStringList()<<"Transport Layer Security"));
                    }
                }
            }else if(packageType == UDP || packageType == DNS){
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
                if(packageType == DNS){
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
            }else if(packageType == ICMP){
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
        // the ethernet may have padding to ensure that the minimum length of the data packet is greater than 46
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

/*
 * on_lineEdit_returnPressed
 * if you press the enter key,when capture is stopped
 * table will Filter eligible item
*/
void MainWindow::on_lineEdit_returnPressed()
{
    QString text = ui->lineEdit->text();
    text = text.toUpper();
    QString target = "#";
    if(text == "" || text == "UDP" || text == "TCP" || text == "DNS" || text == "ARP"|| text == "ICMP"|| text == "SSL" || text == "TLS"){
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

/*
 * on_lineEdit_textChanged
 * when text at lineEdit changed,it will check input information is correct or not
 * if it is corrected,the color is green or it will be red
*/
void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    QString text = arg1;
    text = text.toLower();
    if(text == "" || text == "udp" || text == "tcp" || text == "dns" || text == "arp" || text == "icmp" || text == "tls" || text == "ssl"){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
}

/*
 * on_tableWidget_currentCellChanged
 * this fucntion can response to up-down key
 * when you use the keyboard to manipulate,this bottom treewidget will also show information as well as you use mouse
*/
void MainWindow::on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn)
{
    if((currentRow != previousRow) && previousRow >= 0){
        on_tableWidget_cellClicked(currentRow,currentColumn);
    }else return;
}
