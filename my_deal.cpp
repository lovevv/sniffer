#include "my_deal.h"

my_deal::my_deal()
{

}

void my_deal::run()
{

}

void my_deal::udp_deal(const u_char *packet, int ip_head_l)//5
{
    udp_head *udp_data=(udp_head *)(packet+14+ip_head_l);
    QString general_udpdeal;
    QString srcport;
    QString dstport;
    QString length;
    QString checksum;

    //
    general_udpdeal.append("User Datagram Protocol,Src port: ");
    general_udpdeal.append(QString::number(ntohs(udp_data->sport),10));
    general_udpdeal.append(", Dst port: ");
    general_udpdeal.append(QString::number(ntohs(udp_data->dport),10));

    //
    srcport.append("Source port: ");
    srcport.append(QString::number(ntohs(udp_data->sport),10));
    //
    dstport.append("Destination port: ");
    dstport.append(QString::number(ntohs(udp_data->dport),10));
    //
    length.append("Length: ");
    length.append(QString::number(ntohs(udp_data->len),10));
//
    checksum.append("Checksum: ");
    checksum.append(QString::number(ntohs(udp_data->check_sum),10));
    //
    msg_string.append(general_udpdeal);
    msg_string.append(srcport);
    msg_string.append(dstport);
    msg_string.append(length);
    msg_string.append(checksum);

}

void my_deal::format_print(pcap_pkthdr *format_pkthdr, const u_char *format_packet)//1
{

    char temp[10];
    QString string;
    for(int i=0;i<(int)format_pkthdr->len;i++)
    {
        sprintf(temp,"%02x",format_packet[i]);
        string.append(temp);
        string.append(" ");
        if((i+1)%16==0)
        {
            string.append("             ");
            int temp_t=i+1;
            for(int j=temp_t-16;j<=temp_t-1;j++)
            {
                if(isprint(format_packet[j]))//panduan shifou shi ke daying de zifu zai AScII
                {
                    sprintf(temp,"%c",(char *)format_packet[j]);
                    string.append(temp);
                }
                else
                    string.append(".");
            }
            string.append("\n");
        }
    }
    msg_string.append(string);
}

void my_deal::save_packet(struct pcap_pkthdr *cap_pkthdr,const u_char *cap_packet,int id)
{

//    const u_char **apacket=new const u_char*(cap_packet);// get the packet been selected
  //  struct pcap_pkthdr **apkthdr=new struct pcap_pkthdr *(cap_pkthdr);
   // mydata.append(cap_packet);
    //mydata[id]=cap_packet;
   // mypkthdr.append(cap_pkthdr);
   // mypkthdr[id]=cap_pkthdr;
    msg_string.clear();
    int isbig=Is_big_endia();
    int ishttp;
    QString temp;
    general_deal(cap_pkthdr,cap_packet,id);//4
    link_deal(cap_packet);//link_deak is ok 4
    ip_deal(cap_pkthdr,cap_packet,isbig);//14

    qDebug("int the save packet  protocol is %s",ip_protocol.toLocal8Bit().data());
    if(ip_protocol=="TCP")
    {
     //Is http
        temp.clear();
        if((ishttp=Ishttp(cap_pkthdr,cap_packet,temp))==0)
            tcp_deal(cap_packet);//9
        else
        {

            msg_string[18]="Protocol: HTTP";
            tcp_deal(cap_packet);
            msg_string.append(temp);//
        }
    }
    else if(ip_protocol=="UDP")
        udp_deal(cap_packet,ip_length);//4

    format_print(cap_pkthdr,cap_packet);//1

    fin_string.append(msg_string);
    qDebug("fin_string length is %d",fin_string.length());
    qDebug("int id is %d",id);

    //emit show_capturedata_ui(cap_pkthdr,cap_packet,id,ishttp);
    emit show_capturedata_ui(cap_pkthdr,cap_packet,id,ishttp);
}

int my_deal::Ishttp(pcap_pkthdr *cap_pkthdr, const u_char *cap_packet,QString &datastring)
{
    ip_head *ip_data=(ip_head*)(cap_packet+14);
    int ip_totollen=ntohs(ip_data->total_len);
    bool Is_http=false;
    char *temp_ipdata=( char *)ip_data;
    int buffsize=0;
    char buffer[1518];
    for(int i=0;i<ip_totollen;i++)
    {
        if(!Is_http&&(i+3<ip_totollen&&strncmp(temp_ipdata+i,"GET",strlen("GET"))==0)
                      ||(i+4<ip_totollen&&strncmp(temp_ipdata+i,"POST",strlen("POST"))==0) )
            Is_http=true;
        if(!Is_http && i+8<ip_totollen && strncmp(temp_ipdata+i,"HTTP/1.1",strlen("HTTP/1.1"))==0)
            Is_http=true;
        if(Is_http)
            buffer[buffsize++]=temp_ipdata[i];
    }

    if(Is_http)
    {
//        int a=1;
  //      qDebug("in the Ishttp the data of %d",a);
        buffer[buffsize]='\0';
        datastring.append(buffer);
        return 1;//Is http
    }
    else
        return 0;    //Not http
}


void my_deal::general_deal(const pcap_pkthdr *link_pkthdr, const u_char *link_packet,int id)// 4 string
{

    QString general_msg="Frame "+QString::number(id,10)+": "+
            QString::number(link_pkthdr->len,10)+" bytes on wire, "+QString::number(link_pkthdr->caplen,10)+" bytes capatured";
    //qDebug("generl deal is %s",general_msg.toLocal8Bit().data());
    QString framenumber="Frame Number: "+QString::number(id,10);
    QString framelength="Frame Length: "+QString::number(link_pkthdr->len,10)+" bytes ("+QString::number(link_pkthdr->len*8,10)+" bits)";
    QString caplength="Capture Length: "+QString::number(link_pkthdr->caplen,10)+" bytes ("+QString::number(link_pkthdr->caplen*8,10)+" bits)";

    msg_string.append(general_msg);
    msg_string.append(framenumber);
//    msg_string.append("pp");
  //  msg_string.append("qq");
    msg_string.append(framelength);
    msg_string.append(caplength);


}

void my_deal::link_type_judge(u_char judge_type0, u_char judge_type1, QString &type)
{
    u_char type_result[3];
    sprintf((char *)type_result,"%02x%02x",judge_type0,judge_type1);
    if(strcmp("0800",(char *)type_result)==0)
        type="IP";
    else if(strcmp("0806",(char *)type_result)==0)
        type="ARP";
    else if(strcmp("880B",(char *)type_result)==0)
        type="PPP";
    else if(strcmp("8035",(char *)type_result)==0)
        type="RARP";
    else
        type="Unknow";
}

void my_deal::link_deal(const u_char *link_packet)//4 string
{
    link_head *link_data=(link_head *)link_packet;
    char temp[20];
    QString link_msg="Ethernet II, Src: ";
    QString desination;
    QString source;
    QString types;

    for(int i=0;i<6;i++)
    {
        sprintf(temp,"%02x",link_data->src_mac[i]);
      //  qDebug("mac mac mac  %s",temp);
        source.append(temp);
        if(i!=5)
            source.append(":");
    }
    link_msg.append(source);
    link_msg.append(", Dst: ");
    for(int i=0;i<6;i++)
    {
        sprintf(temp,"%02x",link_data->dest_mac[i]);
      //  qDebug("mac mac mac  %s",temp);
        desination.append(temp);
        if(i!=5)
            desination.append(":");
    }
    link_msg.append(desination);
    link_type_judge(link_data->type[0],link_data->type[1],types);
   // qDebug("mac is %s",link_msg.toLocal8Bit().data());
    QString fin_destination="Destination: "+desination;
    QString fin_source="Source: "+source;
    QString fin_types="Types: "+types;
    msg_string.append(link_msg);
    msg_string.append(fin_destination);
    msg_string.append(fin_source);
    msg_string.append(fin_types);
}

int my_deal::Is_big_endia()
{
    union test
    {
        short int a;
        char b;
    }test;
    test.a=0x1234;
    if(test.b==0x12)
        return 1;
    else
        return 0;
}

void my_deal::get_protocol(ip_head *temp_data, QString &proto)
{
    switch(temp_data->protocol){
        case 1:
            //strcpy(protocol,"ICMP");
            proto="ICMP";
            break;
        case 2:
            //strcpy(protocol,"IGMP");
            proto="IGMP";
            break;
        case 3:
          //  strcpy(protocol,"GGP");
            proto="GGP";
            break;
        case 4:
            //strcpy(protocol,"IP");
            proto="IP";
            break;
        case 5:
          //  strcpy(protocol,"ST");
            proto="ST";
            break;
        case 6:
            //strcpy(protocol,"TCP");
            proto="TCP";
            break;
        case 17:
            //strcpy(protocol,"UDP");
            proto="UDP";
            break;
        case 41:
            proto="IPv6";
            break;
        case 58:
            proto="IPv6-ICMP";
            break;
        case 89:
            proto="OSPFIGP";
            break;
        case 92:
            proto="MTP";
            break;
        case 115:
            proto="L2TP";
            break;
        case 118:
            proto="STP";
            break;
        case 124:
            proto="ISIS";
            break;
        default:
            //strcpy(protocol,"protocol unkown");
            proto="Protocol Unknow";
        }
}

void my_deal::ip_deal(const pcap_pkthdr *ip_pkthdr, const u_char *ip_packet, int ip_isbig)//14
{
    QString general_ipdata;
    QString version;
    QString headlen;
    QString differservice;
    QString totallength;
    QString Identification;
    QString DF;
    QString MF;
    QString flagmentoffset;
    QString ttl;
    QString protocol;
    QString checksum;
    QString srcip;
    QString dstip;

    if(ip_pkthdr->len>14)
    {
        ip_head *ip_data=(ip_head *)(ip_packet+14);
        if(ip_isbig==0)
        {
            //
            general_ipdata.append("Internet Protocol Version ");
            general_ipdata.append(QString::number(ip_data->version>>4,10));
            general_ipdata.append(", Src: ");
            general_ipdata.append(inet_ntoa(*(in_addr *)ip_data->src_ip));
            general_ipdata.append(", Dst: ");
            general_ipdata.append(inet_ntoa(*(in_addr *)ip_data->dest_ip));
            //
            version.append("Version: ");
            version.append(QString::number(ip_data->version>>4,10));
            //
            headlen.append("Header Length: ");
            headlen.append(QString::number((ip_data->ip_head_len&0x0f)*4,10));
            //*ip_head_len=(ip_data->ip_head_len&0x0f)*4;
            ip_length=(ip_data->ip_head_len&0x0f)*4;
            //
            char temp[10];
            sprintf(temp,"%02x",ip_data->service_type);
            differservice.append("Differentitaed Services Field: 0x");
            differservice.append(temp);
            //
            totallength.append("Total Length: ");
            totallength.append(QString::number(ntohs(ip_data->total_len)));
            //
            Identification.append("Identification: 0x");
            sprintf(temp,"%02x",ntohs(ip_data->ident));
            Identification.append(temp);
            //DF
            DF.append("DF: ");
            DF.append(QString::number((ntohs(ip_data->flags)>>14)&0x01,10));
            //MF
            MF.append("MF: ");
            MF.append(QString::number((ntohs(ip_data->flags)>>13)&0x01,10));
            //
            flagmentoffset.append("Flagment Offset: ");
            flagmentoffset.append(QString::number(ntohs(ip_data->flagoff)&0x1fff,10));
            //ttl
            ttl.append("Time to live: ");
            ttl.append(QString::number(ip_data->ttl,10));
            //protocol
            protocol.append("Protocol: ");
            QString tempproto;
            get_protocol(ip_data,tempproto);
            ip_protocol=tempproto;
            protocol.append(tempproto);

            //checksum
            checksum.append("Header checksum: ");
            checksum.append(QString::number(ntohs(ip_data->check_sum),10));
            //source ip
            srcip.append("Source: ");
            srcip.append(inet_ntoa(*(in_addr *)ip_data->src_ip));
            //
            dstip.append("Dstination: ");
            dstip.append(inet_ntoa(*(in_addr *)ip_data->dest_ip));
        }
    }
    msg_string.append(general_ipdata);
    msg_string.append(version);
    msg_string.append(headlen);
    msg_string.append(differservice);

    msg_string.append(totallength);
    msg_string.append(Identification);
    msg_string.append(DF);
    msg_string.append(MF);

    msg_string.append(flagmentoffset);
    msg_string.append(ttl);
    msg_string.append(protocol);
    msg_string.append(checksum);

    msg_string.append(srcip);
    msg_string.append(dstip);

}

void my_deal::tcp_deal(const u_char *packet)//9
{
    tcp_head *tcp_data=(tcp_head*)(packet+14+ip_length);
    QString general_tcpdata;
    QString srcport;
    QString dstport;
    QString seqnumber;

    QString acknumber;
    QString headerlength;
    QString flags;
    QString windowsize;
    QString checksum;

    if(Is_big_endia()==0)
    {
        //
        general_tcpdata.append("Transmition Control Protocol, Src port: ");
        general_tcpdata.append(QString::number(ntohs(tcp_data->sport),10));
        general_tcpdata.append(", Dst port: ");
        general_tcpdata.append(QString::number(ntohs(tcp_data->dport),10));
        general_tcpdata.append(", Seq: ");
        general_tcpdata.append(QString::number(ntohl(tcp_data->seq),10));
        general_tcpdata.append(", Ack: ");
        general_tcpdata.append(QString::number(ntohl(tcp_data->ack),10));
        general_tcpdata.append(", len: ");
        general_tcpdata.append(QString::number((ntohs(tcp_data->many)>>12)*4,10));
        //
        srcport.append("Source port: ");
        srcport.append(QString::number(ntohs(tcp_data->sport),10));
        //
        dstport.append("Destination port: ");
        dstport.append(QString::number(ntohs(tcp_data->dport),10));
        //
        seqnumber.append("Sequence number: ");
        seqnumber.append(QString::number(ntohl(tcp_data->seq),10));
        //
        acknumber.append("Acknowlegment number: ");
        acknumber.append(QString::number(ntohl(tcp_data->ack),10));
        //
        headerlength.append("Header length: ");
        headerlength.append(QString::number((ntohs(tcp_data->many)>>12)*4,10));
        //
        flags.append("Flags: URG:");
        flags.append(QString::number((ntohs(tcp_data->many>>5)&0x0001),10));
        flags.append(" ,ACK:");
        flags.append(QString::number((ntohs(tcp_data->many>>4)&0x0001),10));
        flags.append(", PSH:");
        flags.append(QString::number((ntohs(tcp_data->many>>3)&0x0001),10));
        flags.append(" ,RST:");
        flags.append(QString::number((ntohs(tcp_data->many>>2)&0x0001),10));
        flags.append(", SYN:");
        flags.append(QString::number((ntohs(tcp_data->many>>1)&0x0001),10));
        flags.append(", FIN:");
        flags.append(QString::number((ntohs(tcp_data->many)&0x0001),10));
        //
        windowsize.append("Window size size: ");
        windowsize.append(QString::number(ntohs(tcp_data->window),10));
        //
        checksum.append("Checksum: ");
        checksum.append(QString::number(ntohs(tcp_data->check_sum),10));
    }
    msg_string.append(general_tcpdata);
    msg_string.append(srcport);
    msg_string.append(dstport);
    msg_string.append(seqnumber);

    msg_string.append(acknumber);
    msg_string.append(headerlength);
    msg_string.append(flags);
    msg_string.append(windowsize);
    msg_string.append(checksum);
}


void my_deal::get_selectrow(int row, int cloumn)
{
    //qDebug("get the select row is %d",row);
    //qDebug("get the select cloumn is %d",cloumn);
    //msg_string.clear();//
    //qDebug("msg_string length is %d",msg_string.length());
    choserow=row;
    chosecloumn=cloumn;
  //  int isbig;

    //isbig=Isndia_big_e();

    qDebug("get the row is %d",row);

    //print of the data of the select row
    //const u_char *packet=mydata[row];// get the packet been selected
  //  struct pcap_pkthdr *pkthdr=mypkthdr[row];
//    char temp[10];
//    QString string;
//    for(int i=0;i<(int)pkthdr->len;i++)
//    {
//        sprintf(temp,"%02x",packet[i]);
//        string.append(temp);
//        string.append(" ");
//        if((i+1)%16==0)
//            string.append("\n");
//    }
//    qDebug("data is \n%s",string.toLocal8Bit().data());

//       general_deal(mypkthdr.at(row),mydata.at(row));
//    link_deal(mydata.at(row));//link_deak is ok
//    ip_deal(mypkthdr.at(row),mydata.at(row),isbig);
//    tcp_deal(mydata.at(row));
    msg_string=fin_string[row];

    emit show_intree(msg_string);


}
