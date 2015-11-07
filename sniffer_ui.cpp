#include "sniffer_ui.h"
#include "ui_sniffer_ui.h"

sniffer_ui::sniffer_ui(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::sniffer_ui)
{
    //进行设置菜单和工具栏
    ui->setupUi(this);
    sniffer=new my_sniffer();//创建一个sniffer的对象
    mydeal=new my_deal();
  //  delete sniffer;
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止编辑表格
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows); //设置表格为选择整行
    ui->tableWidget->setShowGrid(false); //设置不显示格子线
    ui->tableWidget->setStyleSheet("background-color:rgba(200,255,255,255)");//shezhi beijingse
    ui->treeWidget->setHeaderHidden(true);//hide the head

  //  connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),this,SLOT(get_selectrow(int,int)));
    //ui->tableWidget->currentIndex().row()
    //ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows); //设置选择行为时每次选择一行
   // ui->tableWidget->resizeColumnsToContents();



   // connect(sniffer,SIGNAL(deliver_declist(QStringList)),this,SLOT(recev_declist(QStringList)));
   // connect(this,SIGNAL(sendnametosniffer(char*)),sniffer,SLOT(open_dev(char*)));
    //connect(this,SIGNAL(sendnametosniffer(char*,char*)),sniffer,SLOT(open_dev(char*,char*)));
    //connect(sniffer,SIGNAL(send_capture_pcaket(pcap_pkthdr*,const u_char*)),this,SLOT(revice_capturepacket(pcap_pkthdr*,const u_char*)));
  //避免速度不同步造成数据保存顺序与界面显示次序不一至
  //  connect(sniffer,SIGNAL(send_capture_pcaket(pcap_pkthdr*,const u_char*,int)),this,SLOT(revice_capturepacket(pcap_pkthdr*,const u_char*,int)));
//    connect(sniffer,SIGNAL(send_capture_pcaket(pcap_pkthdr*,const u_char*,int)),mydeal,
   // connect(sniffer,SIGNAL(send_capture_packettomydeal(const u_char*)),mydeal,SLOT(save_packet(const u_char*)));//save packet
    //connect(sniffer,SIGNAL(send_capture_packettomydeal(pcap_pkthdr*,const u_char*)),mydeal,SLOT(save_packet(pcap_pkthdr*,const u_char*)));
    connect(sniffer,SIGNAL(send_capture_pcaket(pcap_pkthdr*,const u_char*,int)),mydeal,SLOT(save_packet(pcap_pkthdr*,const u_char*,int)));
    connect(mydeal,SIGNAL(show_capturedata_ui(pcap_pkthdr*,const u_char*,int,int)),this,SLOT(revice_capturepacket(pcap_pkthdr*,const u_char*,int,int)));

    connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),mydeal,SLOT(get_selectrow(int,int)));
    connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),this,SLOT(record_optionseq(int,int)));


    //connect(mydeal,SIGNAL(show_intree(QStringList)),this,
    connect(mydeal,SIGNAL(show_intree(QList<QString>)),this,SLOT(show_treewidget(QList<QString>)));
    action=new QAction(tr("chose"),this);
    action->setShortcut(QKeySequence::Open);
    action->setIcon(QIcon(":/new/prefix1/chose.png"));
    action->setStatusTip(tr("Open a file"));

    start_cap=new QAction(tr("start"),this);
    start_cap->setShortcut(QKeySequence::New);//Ctrl+N to start a captrue is ok
    start_cap->setStatusTip(tr("start capture the data"));
    start_cap->setIcon(QIcon(":/new/prefix1/start.png"));

    end_cap=new QAction(tr("stop"),this);
    end_cap->setStatusTip(tr("stop capture the data"));
    end_cap->setIcon(QIcon(":/new/prefix1/stop.png"));

    QAction *left =new QAction(tr("left"),this);
    left->setStatusTip(tr("the privious data"));
    left->setIcon(QIcon(":/new/prefix1/left.png"));

    QAction *right =new QAction(tr("right"),this);
    right->setStatusTip(tr("the next data"));
    right->setIcon(QIcon(":/new/prefix1/right.png"));

    QAction *about=new QAction(tr("about"),this);
    about->setStatusTip(tr("developer information"));
   // about->setIcon(QIcon(":/new/prefix1/stop.png"));

    QMenu *file = menuBar()->addMenu(tr("&File"));
    QMenu *help=menuBar()->addMenu(tr("&help"));

   // menuBar()->addMenu(tr("test"));
    //file->addMenu("pp");
  //  file->addMenu("test");
   // file->add
    file->addAction(action);
    file->addAction(start_cap);
    help->addAction(about);

    QToolBar *toolBar = addToolBar(tr("chose"));
    toolBar->addAction(action);
    QToolBar *toolBar2 = addToolBar(tr("start"));
    toolBar2->addAction(start_cap);
    QToolBar *toolBar3 = addToolBar(tr("stop"));
    toolBar3->addAction(end_cap);

    QToolBar *toolBar4 = addToolBar(tr("left"));
    toolBar4->addAction(left);
    QToolBar *toolBar5 = addToolBar(tr("right"));
    toolBar5->addAction(right);
  //  which_dev=new chose_dev("chose_dev");

  //  connect(left,SIGNAL(triggered()),this,
    connect(action,SIGNAL(triggered()),this,SLOT(show_chosedev()));
    connect(sniffer,SIGNAL(chose_device()),this,SLOT(show_chosedev()));
    connect(start_cap,SIGNAL(triggered()),sniffer,SLOT(start_capturepacket()));
    connect(end_cap,SIGNAL(triggered()),sniffer,SLOT(end_capturepacket()));
    connect(about,SIGNAL(triggered()),this,SLOT(show_development()));
}



void sniffer_ui::record_optionseq(int row,int cloumn)
{
    chose_seq.append(row);
}

void sniffer_ui::show_development()
{
    QMessageBox *msg=new QMessageBox(QMessageBox::NoIcon,"Development Info",
                        "developer : sunchanghui\n\nContact : sunchanghui@iie.ac.cn\n\nCopyLeft : Now---Ferever\n\n",NULL,NULL);
    msg->show();
}

void sniffer_ui::show_treewidget(QList<QString> list)
{
    //if(ui->treeWidget->)
    ui->treeWidget->clear();//clear the data in the pervious success

    //general
    QTreeWidgetItem *link_data=new QTreeWidgetItem(ui->treeWidget,QStringList(list[0]));
    QTreeWidgetItem *link_data_framenumber=new QTreeWidgetItem(link_data,QStringList(list[1]));
    QTreeWidgetItem *link_data_framelength=new QTreeWidgetItem(link_data,QStringList(list[2]));
    QTreeWidgetItem *link_data_capturelen=new QTreeWidgetItem(link_data,QStringList(list[3]));
    //link
    QTreeWidgetItem *link_deal=new QTreeWidgetItem(ui->treeWidget,QStringList(list[4]));
    QTreeWidgetItem *link_deal_destination=new QTreeWidgetItem(link_deal,QStringList(list[5]));
    QTreeWidgetItem *link_deal_source=new QTreeWidgetItem(link_deal,QStringList(list[6]));
    QTreeWidgetItem *link_deal_type=new QTreeWidgetItem(link_deal,QStringList(list[7]));
    //ip
    QTreeWidgetItem *ip_deal=new QTreeWidgetItem(ui->treeWidget,QStringList(list[8]));
    QTreeWidgetItem *ip_deal_version=new QTreeWidgetItem(ip_deal,QStringList(list[9]));
    QTreeWidgetItem *ip_deal_headlen=new QTreeWidgetItem(ip_deal,QStringList(list[10]));
    QTreeWidgetItem *ip_deal_differservice=new QTreeWidgetItem(ip_deal,QStringList(list[11]));
    QTreeWidgetItem *ip_deal_totallength=new QTreeWidgetItem(ip_deal,QStringList(list[12]));
    QTreeWidgetItem *ip_deal_identification=new QTreeWidgetItem(ip_deal,QStringList(list[13]));
    QTreeWidgetItem *ip_deal_DF=new QTreeWidgetItem(ip_deal,QStringList(list[14]));
    QTreeWidgetItem *ip_deal_MF=new QTreeWidgetItem(ip_deal,QStringList(list[15]));
    QTreeWidgetItem *ip_deal_flagmentoffset=new QTreeWidgetItem(ip_deal,QStringList(list[16]));
    QTreeWidgetItem *ip_deal_ttl=new QTreeWidgetItem(ip_deal,QStringList(list[17]));
    QTreeWidgetItem *ip_deal_protocol=new QTreeWidgetItem(ip_deal,QStringList(list[18]));
    QTreeWidgetItem *ip_deal_checksum=new QTreeWidgetItem(ip_deal,QStringList(list[19]));
    QTreeWidgetItem *ip_deal_srcip=new QTreeWidgetItem(ip_deal,QStringList(list[20]));
    QTreeWidgetItem *ip_deal_dstip=new QTreeWidgetItem(ip_deal,QStringList(list[21]));
    if(list[18]=="Protocol: TCP"||list[18]=="Protocol: HTTP")
    //tcp
   {

        QTreeWidgetItem *tcp_deal=new QTreeWidgetItem(ui->treeWidget,QStringList(list[22]));
        QTreeWidgetItem *tcp_deal_srcport=new QTreeWidgetItem(tcp_deal,QStringList(list[23]));
        QTreeWidgetItem *tcp_deal_dstport=new QTreeWidgetItem(tcp_deal,QStringList(list[24]));
        QTreeWidgetItem *tcp_deal_seqnumber=new QTreeWidgetItem(tcp_deal,QStringList(list[25]));
        QTreeWidgetItem *tcp_deal_ack=new QTreeWidgetItem(tcp_deal,QStringList(list[26]));
        QTreeWidgetItem *tcp_deal_headerlength=new QTreeWidgetItem(tcp_deal,QStringList(list[27]));
        QTreeWidgetItem *tcp_deal_flags=new QTreeWidgetItem(tcp_deal,QStringList(list[28]));
        QTreeWidgetItem *tcp_deal_windowsize=new QTreeWidgetItem(tcp_deal,QStringList(list[29]));
        QTreeWidgetItem *tcp_deal_checksum=new QTreeWidgetItem(tcp_deal,QStringList(list[30]));
        if(list[18]=="Protocol: HTTP")
        {
            QTreeWidgetItem *http_deal=new QTreeWidgetItem(ui->treeWidget,QStringList(list[31]));
            ui->textBrowser->clearHistory();
            ui->textBrowser->clear();
            ui->textBrowser->append(list[32]);
        }
        else
        {
            ui->textBrowser->clearHistory();
            ui->textBrowser->clear();
            ui->textBrowser->append(list[31]);
        }
    }
    else if(list[18]=="Protocol: UDP")
    {
         QTreeWidgetItem *udp_deal=new QTreeWidgetItem(ui->treeWidget,QStringList(list[22]));
         QTreeWidgetItem *udp_deal_srcport=new QTreeWidgetItem(udp_deal,QStringList(list[23]));
         QTreeWidgetItem *udp_deal_dstport=new QTreeWidgetItem(udp_deal,QStringList(list[24]));
         QTreeWidgetItem *udp_deal_length=new QTreeWidgetItem(udp_deal,QStringList(list[25]));
         QTreeWidgetItem *udp_deal_checksum=new QTreeWidgetItem(udp_deal,QStringList(list[26]));
         ui->textBrowser->clearHistory();
         ui->textBrowser->clear();
         ui->textBrowser->append(list[27]);
    }

}

void sniffer_ui::get_protocol(ip_head *temp_data, QString &protocol)
{
    switch(temp_data->protocol){
        case 1:
            //strcpy(protocol,"ICMP");
            protocol="ICMP";
            break;
        case 2:
           // strcpy(protocol,"IGMP");
           protocol="IGMP";
            break;
        case 3:
          //  strcpy(protocol,"GGP");
            protocol="GGP";
            break;
        case 4:
            //strcpy(protocol,"IP");
            protocol="IP";
            break;
        case 5:
          //  strcpy(protocol,"ST");
            //break;
        case 6:
            //strcpy(protocol,"TCP");
            protocol="TCP";
            break;
        case 17:
                //strcpy(protocol,"UDP");
            protocol="UDP";
            break;
        case 41:
            protocol="IPv6";
            break;
        case 58:
            protocol="IPv6-ICMP";
            break;
        case 89:
            protocol="OSPFIGP";
            break;
        case 92:
            protocol="MTP";
            break;
        case 115:
            protocol="L2TP";
            break;
        case 118:
            protocol="STP";
            break;
        case 124:
            protocol="ISIS";
            break;
        default:
            //strcpy(protocol,"protocol unkown");
            protocol="protocol unkoow";
        }
}

void sniffer_ui::revice_capturepacket(pcap_pkthdr *rec_pkthdr,
                                      const u_char *rec_packet,int rec_frameid,int httpis)//logic success
{
    qDebug("recive data packet in the ui  httpis is %d",httpis);

    int row_count = ui->tableWidget->rowCount(); //获取表单行数
    qDebug("first row is %d",row_count);
    ui->tableWidget->insertRow(row_count); //插入新行

    QTableWidgetItem *item = new QTableWidgetItem();
    QTableWidgetItem *item1 = new QTableWidgetItem();
    QTableWidgetItem *item2 = new QTableWidgetItem();
    QTableWidgetItem *item3 = new QTableWidgetItem();
    QTableWidgetItem *item4 = new QTableWidgetItem();
    QTableWidgetItem *item5 = new QTableWidgetItem();
    QTableWidgetItem *item6 = new QTableWidgetItem();

    QDateTime time=QDateTime::currentDateTime();
    QString str_time = time.toString("hh:mm:ss:zzz"); //设置显示格式

    QString src_ipaddress;
    QString dst_ipaddress;
    QString protocol;
    link_head *link_data=(link_head *)(rec_packet);
   // qDebug("len of the linkdata  %d",rec_pkthdr->len);
    if(rec_pkthdr->len>14)
    {
        ip_head *ip_data=(ip_head*)(rec_packet+14);

        src_ipaddress=inet_ntoa(*(in_addr *)ip_data->src_ip);
        dst_ipaddress=inet_ntoa(*(in_addr *)ip_data->dest_ip);
        get_protocol(ip_data,protocol);
        qDebug("protocol : %s",protocol.toLocal8Bit().data());
        if(protocol=="TCP")
            if(httpis==1)
                protocol="HTTP";
        item->setText(QString::number(rec_frameid,10));
        item1->setText(str_time);
        item2->setText(src_ipaddress);
        item3->setText(dst_ipaddress);
        item4->setText(protocol);
        item5->setText(QString::number(rec_pkthdr->len,10));
    }
    ui->tableWidget->setItem(row_count,0,item);
    ui->tableWidget->setItem(row_count,1,item1);
    ui->tableWidget->setItem(row_count,2,item2);
    ui->tableWidget->setItem(row_count,3,item3);
    ui->tableWidget->setItem(row_count,4,item4);
    ui->tableWidget->setItem(row_count,5,item5);
    ui->tableWidget->setItem(row_count,6,item6);

    //设置样式为灰色
    QColor color("blue");
    item1->setTextColor(color);
    item2->setTextColor(color);
    item3->setTextColor(color);
    item4->setTextColor(color);
    item5->setTextColor(color);
    item6->setTextColor(color);
}

sniffer_ui::~sniffer_ui()
{
    delete ui;
}

void sniffer_ui::show_chosedev()
{
    //printf("hello \n");
    //qDebug<<"test";

    which_dev=new chose_dev();
    connect(this,SIGNAL(command_chose_request_tosniffer()),which_dev,SLOT(recive_command()));
    connect(sniffer,SIGNAL(send_devlist(QStringList)),which_dev,SLOT(rev_dev(QStringList)));
    connect(which_dev,SIGNAL(send_devname_filter(char*,char*)),sniffer,SLOT(rev_devname_filter(char*,char*)));
    connect(which_dev,SIGNAL(request_dev()),sniffer,SLOT(rev_request()));
    emit command_chose_request_tosniffer();
    which_dev->show();
    return;
}



void sniffer_ui::rev_request()
{
    qDebug("in the rev_request");
    //emit request_dev(ui_list);
}
