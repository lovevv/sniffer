#ifndef MY_SNIFFER_H
#define MY_SNIFFER_H
#include "Packet_Format.h"
#include <QObject>
#include <QStringList>
#include <QDebug>
#include<QThread>
#include <QMessageBox>


class my_sniffer:public QThread//change a thread way can solve the mainwindow dead problem
{
    Q_OBJECT

public:
    virtual void run();
    explicit my_sniffer();
    void mypcap_findalldevs();
    int mypcap_openlive();
    void mypcap_compile();
    void mypcap_setfilter();
    void mypcap_loop();

public slots:
    void rev_request();
    void rev_devname_filter(char *devname,char *filters);
    void start_capturepacket();
    void end_capturepacket();

signals:
    void send_devlist(QStringList list);
    void send_capture_pcaket(struct pcap_pkthdr *cap_pkthdr,const u_char *cap_packet,int frameid);
    void send_capture_packettomydeal(struct pcap_pkthdr *cap_pkthdr,const u_char *cap_packet);//
    void chose_device();
private:
    char dev_name[20];//device name
    char filter_string[50];
    pcap_t *dev_haddle;//opetion handle
    bpf_u_int32 ip_address,ip_mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];//用于进行转换为字符串进行显示
    struct bpf_program fp;
    QStringList listdev;//用于保存设备列表
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    bool stopped;
  //  bool started;

};

#endif // MY_SNIFFER_H
