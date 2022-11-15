#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <Winsock2.h>
#include <iostream>
#include <ntddndis.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#include <fstream>  //�ļ����������;

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
/*�±�����̫����Э���ʽ */
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*Ŀ����̫��ַ*/
    u_int8_t ether_shost[6];  /*Դ��̫����ַ*/
    u_int16_t ether_type;      /*��̫������*/
};

/*ip��ַ��ʽ*/
typedef u_int32_t in_addr_t;

struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IPЭ���ײ�����Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*��������Differentiated Services  Field*/
    u_int16_t ip_length;  /*�ܳ���Total Length*/
    u_int16_t ip_id;         /*��ʶidentification*/
    u_int16_t ip_off;        /*Ƭƫ��*/
    u_int8_t ip_ttl;            /*����ʱ��Time To Live*/
    u_int8_t ip_protocol;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    u_int16_t ip_checksum;  /*�ײ������*/
    struct in_addr  ip_source_address; /*ԴIP*/
    struct in_addr  ip_destination_address; /*Ŀ��IP*/
};

/*����tcpͷ���Ķ���*/
struct tcp_header
{
    u_int16_t tcp_source_port;    //Դ�˿ں�

    u_int16_t tcp_destination_port; //Ŀ�Ķ˿ں�

    u_int32_t tcp_acknowledgement; //���

    u_int32_t tcp_ack; //ȷ�Ϻ��ֶ�
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows; //�����ֶ�
    u_int16_t tcp_checksum; //�����
    u_int16_t tcp_urgent_pointer; //����ָ���ֶ�
};


/*�±�ʵ��IP���ݰ������ĺ�������ethernet_protocol_packet_callback*/
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct ip_header* ip_protocol;   /*ipЭ�����*/
   
    ip_protocol = (struct ip_header*)(packet_content + 14); /*���ip���ݰ�������ȥ����̫ͷ��*/

    printf("%s,", inet_ntoa(ip_protocol->ip_source_address));          /*���Դip��ַ*/
    printf("%s,", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/

}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;                                     /*��̫��Э������*/
    struct ethernet_header* ethernet_protocol;  /*��̫��Э�����*/
    struct ip_header* ip_protocol;   /*ipЭ�����*/

    ip_protocol = (struct ip_header*)(packet_content + 14); /*���ip���ݰ�������ȥ����̫ͷ��*/
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*���һ̫��Э����������*/
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*�����̫������*/

    char timestr[46];
    struct tm* ltime;
    time_t local_tv_sec;

    /*��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
    local_tv_sec = packet_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
    printf("%s,", timestr);//ʱ��
    printf("%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_shost[0],
        ethernet_protocol->ether_shost[1],
        ethernet_protocol->ether_shost[2],
        ethernet_protocol->ether_shost[3],
        ethernet_protocol->ether_shost[4],
        ethernet_protocol->ether_shost[5]);//ԴMac

    printf("%s,", inet_ntoa(ip_protocol->ip_source_address));          /*���Դip��ַ*/

    printf("%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_dhost[0],
        ethernet_protocol->ether_dhost[1],
        ethernet_protocol->ether_dhost[2],
        ethernet_protocol->ether_dhost[3],
        ethernet_protocol->ether_dhost[4],
        ethernet_protocol->ether_dhost[5]);//Ŀ��Mac

    printf("%s,", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/

    printf("%d\n", ntohs(ip_protocol->ip_length));

    FILE* fp = fopen("exp3_3.csv", "a+");
    fprintf(fp,"%s,", timestr);//ʱ��
    fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_shost[0],
        ethernet_protocol->ether_shost[1],
        ethernet_protocol->ether_shost[2],
        ethernet_protocol->ether_shost[3],
        ethernet_protocol->ether_shost[4],
        ethernet_protocol->ether_shost[5]);//ԴMac

    fprintf(fp, "%s,", inet_ntoa(ip_protocol->ip_source_address));          /*���Դip��ַ*/

    fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
        ethernet_protocol->ether_dhost[0],
        ethernet_protocol->ether_dhost[1],
        ethernet_protocol->ether_dhost[2],
        ethernet_protocol->ether_dhost[3],
        ethernet_protocol->ether_dhost[4],
        ethernet_protocol->ether_dhost[5]);//Ŀ��Mac

    fprintf(fp, "%s,", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/

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
    cout << "==========    ����IP���ݰ�    ==========\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum = 0;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* ����������б� */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* ��ӡ������Ϣ */
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
        printf("\nû�з��ֽӿ�!ȷ����װ��LibPcap.\n");
        return -1;
    }

    printf("\n������Ҫѡ��򿪵������� (1-%d)��:\t", i);
    scanf_s("%d", &inum);              //����Ҫѡ��򿪵�������

    if (inum < 1 || inum > i) //�жϺŵĺϷ���
    {
        printf("\n�����ų�����Χ.\n");
        /*�ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* �ҵ�Ҫѡ��������ṹ */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* ��ѡ������� */
    if ((adhandle = pcap_open_live(d->name, /* �豸����*/
        65536,   /* ���ֵ.*/
        /*65536����������������mac�����ϱ�����.*/
        1,       /* ����ģʽ*/

/*
����ģʽ��ָһ̨�����ܹ��������о������������������������������Ŀ�ĵ�ַ�ǲ����������������������ݰ���Ҳ����˵������ģʽ�£�����������еķ������İ�ȫ�������ա�����������£����Խ���ͬһ���������������������ݡ�
*/
1000,     /* ����ʱΪ1��*/
errbuf   /* error buffer*/
)) == NULL)
    {
        fprintf(stderr, "\n�޷���������.\t %s ����LibPcap֧��\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n���� %s...\n", d->description);
    /* ���ڣ����ǲ�����Ҫ�豸�б�, �ͷ��� */
    pcap_freealldevs(alldevs);
    int cnt = -1;
    cout << "\n����Ҫ�������ݰ��ĸ�����:\t\t";
    cin >> cnt;
    /* ��ʼ�Իص��ķ�ʽ�����
    �������ƣ�int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
    �������ܣ��������ݰ�,������Ӧpcap_open_live()�������õĳ�ʱʱ��
    */
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    printf("��MACͳ�ơ�:\n");
    for (int i = 0; i < NUM; i++)
    {
        if (ms[i].flag)break;
        printf("MAC:%02X-%02X-%02X-%02X-%02X-%02X\t����:%d\n", ms[i].host[0], ms[i].host[1], ms[i].host[2],
            ms[i].host[3], ms[i].host[4], ms[i].host[5], ms[i].num);
    }
    printf("��IPͳ�ơ�:\n");
    for (int i = 0; i < NUM; i++)
    {
        if (ips[i].flag)break;
        printf("IP:%s\t����:%d\n", ips[i].ip, ips[i].num);
    }
    return 0;
}