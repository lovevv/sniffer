#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <error.h>
#include <string.h>
#include<sys/types.h>

//链路层数据包头格式
typedef struct link{
    u_char dest_mac[6];
    u_char src_mac[6];
    u_char type[2];
}link_head;

//ip层数据包头格式
typedef struct ip{
    union{
        u_char version;
        u_char ip_head_len;
    };
    u_char service_type;
    u_short total_len;

    u_short ident;
    union{
        u_short flags;
        u_short flagoff;
    };

    u_char ttl;
    u_char protocol;
    u_short check_sum;

    u_char src_ip[4];
    u_char dest_ip[4];
}ip_head;

//tcp 层数据包头格式
typedef struct tcp{
    u_short sport;
    u_short dport;
    u_int32_t seq;
    u_int32_t ack;
    u_short many;//包括首部长度4位+保留字段6位+6个标志位(URG,ACK,PSH,RST,SYN,FIN)
    u_short window;
    u_short check_sum;
    u_short urg_pointer;
}tcp_head;

//udp数据包格式
typedef struct udp{
    u_short sport; //源端口
    u_short dport;//目的端口
    u_short len;//数据总长度
    u_short check_sum;//检验和
}udp_head;


#endif // PACKET_FORMAT_H
