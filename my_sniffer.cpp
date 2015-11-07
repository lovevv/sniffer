#include "my_sniffer.h"

my_sniffer::my_sniffer()
{
   // QObject();
    stopped=false;
    strcpy(dev_name,"\0");
    strcpy(filter_string,"\0");
//    if(dev_name==NULL)
//        qDebug("set the dev_name NUll is success");
//    else
//       {
//        qDebug("dev_name is %s",dev_name);
//        qDebug("set the dev_name nuLL is wrong");
//    }

}


void my_sniffer::run(){
    //qDebug("[[[");
    qDebug("start a thread to get data");
    int packet_id=0;
    while(!stopped)
    {
        int temp;
     //   pkthdr=new struct pcap_pkthdr();
       // packet=new const u_char();

        temp=pcap_next_ex(dev_haddle,&pkthdr,&packet);
        if(temp!=1)
        {
          ;//  qDebug("error in the pcap_next_ex  and  the temp is %d",temp);
        }
        else if(temp==1)
        {
            packet_id++;
            qDebug("in the run");
           // const u_char *packet=mydata[row];// get the packet been selected
            //struct pcap_pkthdr *pkthdr=mypkthdr[row];
            emit send_capture_pcaket(pkthdr,packet,packet_id);
//            emit send_capture_packettomydeal(pkthdr,packet);
        }
      //  stopped=false;
    }
    qDebug("sniffer thread is running");
    if(dev_haddle)
     {
        qDebug("close dev_handle");
        pcap_close(dev_haddle);
     }

}

//char my_sniffer::dev_name=NULL;
void my_sniffer::mypcap_findalldevs()// get dev useful to save
{
    pcap_if_t *all_dev;
    if(pcap_findalldevs(&all_dev,errbuf)==0)
    {
        qDebug(" dec list get success");
        QStringList temp_string;
        while(all_dev->next){
            qDebug("%s",all_dev->name);
            temp_string.append(all_dev->name);
            all_dev=all_dev->next;
        }
        if(temp_string.length()!=listdev.length())
            listdev=temp_string;
    }
    else
        return ;
}

int my_sniffer::mypcap_openlive()//return o i fail ,or return 1 is success
{
    QMessageBox *msg;
    if(strcmp(dev_name,"\0")==0)
     {   //msg=new QMessageBox("No chose device");
        msg=new QMessageBox(QMessageBox::NoIcon,"No chose device",
                            "You don't chose a device ,can't start a captrue!\nChose a device?",QMessageBox::Ok | QMessageBox::Cancel,NULL);
        msg->show();
        if(msg->exec()==QMessageBox::Ok)
        {
            emit chose_device();
            qDebug("chose is ok");
        }
        else
            qDebug("chose if cancel");
        return 0;
    }
    if((dev_haddle=pcap_open_live(dev_name,1518,1,1000,errbuf))==NULL)
    {
        qDebug("openlive is error");
        return 0;
    }
    qDebug("open is successs");
    return 1;
}

void my_sniffer::mypcap_compile()
{
    if(pcap_compile(dev_haddle,&fp,filter_string,1,0)==-1)
    {
        qDebug("compile error: %s",pcap_geterr(dev_haddle));
        return;
    }
    qDebug("compile is success");
}

void my_sniffer::mypcap_setfilter()
{
    if(pcap_setfilter(dev_haddle,&fp)==-1)
    {
        qDebug("setfilter error: %s",pcap_geterr(dev_haddle));
        return;
    }
    qDebug("setfilter is success");
}

void my_sniffer::mypcap_loop()
{
    int packet_id=0;

    while(1){
        int temp;
        temp=pcap_next_ex(dev_haddle,&pkthdr,&packet);
        if(temp!=1)
        {
           ;// qDebug("error in the pcap_next_ex  and  the temp is %d",temp);
        }
        else if(temp==1)
        {
            packet_id++;
            emit send_capture_pcaket(pkthdr,packet,packet_id);
         //   emit send_capture_packettomydeal(pkthdr,packet);
        }
    }
}


void my_sniffer::rev_request()
{
    mypcap_findalldevs();//get shebei liebiao
    qDebug("in the my_sniffer rev_requset");
    emit send_devlist(listdev);
}

void my_sniffer::rev_devname_filter(char *devname, char *filters)
{
    strcpy(dev_name,devname);
    strcpy(filter_string,filters);
    qDebug("in the sniffer rev_devname dev_name is %s",dev_name);
    qDebug("in the sniffer rec_devname filterstring is %s",filter_string);
}

void my_sniffer::start_capturepacket()
{
    qDebug("start capture the packet");
    qDebug("in the sniffer start_capturepacket  dev_name is %s",dev_name);
    qDebug("in the sniffer start_capturepacket  filterstring is %s",filter_string);
    if(mypcap_openlive()==0)
        return;
    if(strcmp(filter_string,"\0")!=0)
    {
        mypcap_compile();
        mypcap_setfilter();
        qDebug("success");
    }
   // mypcap_loop();
        stopped=false;//set to start a new captrue in the next times
        this->start();

}

void  my_sniffer::end_capturepacket()
{
     stopped=true;
}
