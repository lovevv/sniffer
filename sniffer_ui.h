#ifndef SNIFFER_UI_H
#define SNIFFER_UI_H

#include <QMainWindow>
#include <QAction>
#include <QDateTime>
#include <QList>

//#include <QDebug>
#include "my_sniffer.h"
#include "my_deal.h"
#include "chose_dev.h"

namespace Ui {
class sniffer_ui;
}

class sniffer_ui : public QMainWindow
{
    Q_OBJECT

public:
    explicit sniffer_ui(QWidget *parent = 0);
    ~sniffer_ui();
    void get_protocol(ip_head *temp_data,QString &protocol);

public slots:
   void show_chosedev();
   void rev_request();
   void revice_capturepacket(struct pcap_pkthdr *rec_pkthdr,const u_char *rec_packet,int rec_frameid,int httpis);
  // void get_selectrow(int row,int cloumn);
   void show_treewidget(QList<QString> list);
   void show_development();
   void record_optionseq(int row,int cloumn);
signals:
  // void request_dev(QStringList list);
   void sendnametosniffer(char *name,char *flitername);
   void command_chose_request_tosniffer();

private:
    Ui::sniffer_ui *ui;
    my_sniffer *sniffer;//用于进行嗅探  然后再返回到界面上进行现实嗅探的结果
    my_deal *mydeal;
    QAction *action;//行为操作
    QAction *start_cap;
    QAction *end_cap;
    chose_dev *which_dev;
    QList <int> chose_seq;


};

#endif // SNIFFER_UI_H
