#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <Winsock2.h>
#include <iostream>
#include <ntddndis.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#include <fstream>  //文件的输入输出;

#pragma comment(lib,"WS2_32")
//#pragma comment(lib,"wpcap.lib")

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#define NUM 100
struct MAC_Sum
{
    u_int8_t host[6];
    int num=0;
    bool flag=1;
};
struct IP_Sum
{
    char ip[15];
    int num = 0;
    bool flag=1;
};

MAC_Sum ms[NUM];
IP_Sum ips[NUM];
/*下边是以太网的协议格式 */
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*目的以太地址*/
    u_int8_t ether_shost[6];  /*源以太网地址*/
    u_int16_t ether_type;      /*以太网类型*/
};

/*ip地址格式*/
typedef u_int32_t in_addr_t;

struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IP协议首部长度Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*服务类型Differentiated Services  Field*/
    u_int16_t ip_length;  /*总长度Total Length*/
    u_int16_t ip_id;         /*标识identification*/
    u_int16_t ip_off;        /*片偏移*/
    u_int8_t ip_ttl;            /*生存时间Time To Live*/
    u_int8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    u_int16_t ip_checksum;  /*首部检验和*/
    struct in_addr  ip_source_address; /*源IP*/
    struct in_addr  ip_destination_address; /*目的IP*/
};

/*关于tcp头部的定义*/
struct tcp_header
{
    u_int16_t tcp_source_port;    //源端口号

    u_int16_t tcp_destination_port; //目的端口号

    u_int32_t tcp_acknowledgement; //序号

    u_int32_t tcp_ack; //确认号字段
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows; //窗口字段
    u_int16_t tcp_checksum; //检验和
    u_int16_t tcp_urgent_pointer; //紧急指针字段
};


/*下边实现IP数据包分析的函数定义ethernet_protocol_packet_callback*/
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct ip_header* ip_protocol;   /*ip协议变量*/
   
    ip_protocol = (struct ip_header*)(packet_content + 14); /*获得ip数据包的内容去掉以太头部*/

    printf("%s,", inet_ntoa(ip_protocol->ip_source_address));          /*获得源ip地址*/
    printf("%s,", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/

}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;                                     /*以太网协议类型*/
    struct ethernet_header* ethernet_protocol;  /*以太网协议变量*/
    struct ip_header* ip_protocol;   /*ip协议变量*/

    ip_protocol = (struct ip_header*)(packet_content + 14); /*获得ip数据包的内容去掉以太头部*/
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*获得一太网协议数据内容*/
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*获得以太网类型*/

    char timestr[46];
    struct tm* ltime;
    time_t local_tv_sec;

    /*将时间戳转换成可识别的格式 */
    local_tv_sec = packet_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
    printf("%s,", timestr);//时间
    printf("%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_shost[0],
        ethernet_protocol->ether_shost[1],
        ethernet_protocol->ether_shost[2],
        ethernet_protocol->ether_shost[3],
        ethernet_protocol->ether_shost[4],
        ethernet_protocol->ether_shost[5]);//源Mac

    printf("%s,", inet_ntoa(ip_protocol->ip_source_address));          /*获得源ip地址*/

    printf("%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_dhost[0],
        ethernet_protocol->ether_dhost[1],
        ethernet_protocol->ether_dhost[2],
        ethernet_protocol->ether_dhost[3],
        ethernet_protocol->ether_dhost[4],
        ethernet_protocol->ether_dhost[5]);//目标Mac

    printf("%s,", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/

    printf("%d\n", ntohs(ip_protocol->ip_length));

    FILE* fp = fopen("exp3_3.csv", "a+");
    fprintf(fp,"%s,", timestr);//时间
    fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_shost[0],
        ethernet_protocol->ether_shost[1],
        ethernet_protocol->ether_shost[2],
        ethernet_protocol->ether_shost[3],
        ethernet_protocol->ether_shost[4],
        ethernet_protocol->ether_shost[5]);//源Mac

    fprintf(fp, "%s,", inet_ntoa(ip_protocol->ip_source_address));          /*获得源ip地址*/

    fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_dhost[0],
        ethernet_protocol->ether_dhost[1],
        ethernet_protocol->ether_dhost[2],
        ethernet_protocol->ether_dhost[3],
        ethernet_protocol->ether_dhost[4],
        ethernet_protocol->ether_dhost[5]);//目标Mac

    fprintf(fp, "%s,", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/

    fprintf(fp, "%d\n", ntohs(ip_protocol->ip_length));

    for (int i = 0; i < NUM; i++)
    {
        if (ms[i].flag)
        {
            ms[i].host[0] = ethernet_protocol->ether_dhost[0];
            ms[i].host[1] = ethernet_protocol->ether_dhost[1];
            ms[i].host[2] = ethernet_protocol->ether_dhost[2];
            ms[i].host[3] = ethernet_protocol->ether_dhost[3];
            ms[i].host[4] = ethernet_protocol->ether_dhost[4];
            ms[i].host[5] = ethernet_protocol->ether_dhost[5];

            ips[i].num += ntohs(ip_protocol->ip_length);

            ms[i].flag = 0;
            break;
        }
        else if (ms[i].host[0] == ethernet_protocol->ether_dhost[0] &&
            ms[i].host[1] == ethernet_protocol->ether_dhost[1] &&
            ms[i].host[2] == ethernet_protocol->ether_dhost[2] &&
            ms[i].host[3] == ethernet_protocol->ether_dhost[3] &&
            ms[i].host[4] == ethernet_protocol->ether_dhost[4] &&
            ms[i].host[5] == ethernet_protocol->ether_dhost[5])
        {
            ms[i].num+= ntohs(ip_protocol->ip_length);
            break;
        }
    }
    for (int i = 0; i < NUM; i++)
    {
        if (ips[i].flag)
        {
            strcpy(ips[i].ip, (char*)inet_ntoa(ip_protocol->ip_destination_address));
            ips[i].num += ntohs(ip_protocol->ip_length);
            ips[i].flag = 0;
            break;
        }
        else if (strcmp(ips[i].ip, inet_ntoa(ip_protocol->ip_destination_address)) == 0)
        {
            ips[i].num+= ntohs(ip_protocol->ip_length);
            break;
        }
    }
}

int main()
{
    cout << "==========    解析IP数据包    ==========\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum = 0;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获得网卡的列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印网卡信息 */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\n没有发现接口!确保安装了LibPcap.\n");
        return -1;
    }

    printf("\n【输入要选择打开的网卡号 (1-%d)】:\t", i);
    scanf_s("%d", &inum);              //输入要选择打开的网卡号

    if (inum < 1 || inum > i) //判断号的合法性
    {
        printf("\n网卡号超出范围.\n");
        /*释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 找到要选择的网卡结构 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开选择的网卡 */
    if ((adhandle = pcap_open_live(d->name, /* 设备名称*/
        65536,   /* 最大值.*/
        /*65536允许整个包在所有mac电脑上被捕获.*/
        1,       /* 混杂模式*/

/*
混杂模式是指一台主机能够接受所有经过它的数据流，不论这个数据流的目的地址是不是它，它都会接受这个数据包。也就是说，混杂模式下，网卡会把所有的发往它的包全部都接收。在这种情况下，可以接收同一集线器局域网的所有数据。
*/
1000,     /* 读超时为1秒*/
errbuf   /* error buffer*/
)) == NULL)
    {
        fprintf(stderr, "\n无法打开适配器.\t %s 不被LibPcap支持\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n监听 %s...\n", d->description);
    /* 现在，我们不再需要设备列表, 释放它 */
    pcap_freealldevs(alldevs);
    int cnt = -1;
    cout << "\n【将要捕获数据包的个数】:\t\t";
    cin >> cnt;
    /* 开始以回调的方式捕获包
    函数名称：int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
    函数功能：捕获数据包,不会响应pcap_open_live()函数设置的超时时间
    */
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    printf("【MAC统计】:\n");
    for (int i = 0; i < NUM; i++)
    {
        if (ms[i].flag)break;
        printf("MAC:%02X-%02X-%02X-%02X-%02X-%02X\t数量:%d\n", ms[i].host[0], ms[i].host[1], ms[i].host[2],
            ms[i].host[3], ms[i].host[4], ms[i].host[5], ms[i].num);
    }
    printf("【IP统计】:\n");
    for (int i = 0; i < NUM; i++)
    {
        if (ips[i].flag)break;
        printf("IP:%s\t长度:%d\n", ips[i].ip, ips[i].num);
    }
    return 0;
}