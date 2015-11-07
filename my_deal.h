#ifndef MY_DEAL_H
#define MY_DEAL_H

#include <QObject>1
#include <QThread>
#include <QVector>
#include <QVector2D>
#include <QStringList>
#include <QList>

#include "Packet_Format.h"
#include "my_sniffer.h"

class my_deal : public QThread
{
    Q_OBJECT
public:
    virtual void run();
    explicit my_deal();
    void general_deal(const struct pcap_pkthdr *link_pkthdr,const u_char *link_packet,int id);
    void link_deal(const u_char *link_packet);
    void link_type_judge(u_char judge_type0,u_char judge_type1,QString &type);//只进行常见协议的判断分析
    int Is_big_endia();
    void ip_deal(const struct pcap_pkthdr *ip_pkthdr,const u_char *ip_packet,int ip_isbig);
    void get_protocol(ip_head *temp_data,QString &proto);
    void tcp_deal(const u_char *packet);
    void udp_deal(const u_char *packet,int ip_head_l);
    int Ishttp(struct pcap_pkthdr *cap_pkthdr,const u_char *cap_packet,QString &datastring);

    void format_print(struct pcap_pkthdr *format_pkthdr,const u_char *format_packet);

signals:
    void show_intree(QList<QString> listmsg);
    void show_capturedata_ui(struct pcap_pkthdr *link_pkthdr,const u_char *link_packet,int id,int httpis);

public slots:
    void save_packet(struct pcap_pkthdr *cap_pkthdr,const u_char *cap_packet,int id);
    void get_selectrow(int row,int cloumn);

private:
   // QList<const u_char *>mydata;
    //QList<struct pcap_pkthdr *>mypkthdr;
    //QStringList msg_string;
    QList<QString>  msg_string;

    //QStringList fin_string;//save the
//    QList< (QList<QString>) > fin_string;
    QList < QList<QString> > fin_string;  //attention the format to define the double QList is ok
    int choserow;
    int chosecloumn;
    QString ip_protocol;
    int ip_length;


};

#endif // MY_DEAL_H
