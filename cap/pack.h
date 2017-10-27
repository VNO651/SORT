#ifndef PACK_H
#define PACK_H
#include <QVector>
#include "header.h"
#endif // PACK_H

class pack
{
public:
    pack();
    pack(int num);
    ~pack();
    pack(pack &temp);
    pack &operator = (pack &temp);
    QVector<const struct sniff_ip *> ip;
    QVector<const struct sniff_tcp *> tcp;
    QVector<u_char *> payload;
    QVector<const struct sniff_ethernet *> ethernet;
    QVector<struct pcap_pkthdr *> headers;
    QVector<u_char*> packets;
    int _num=ip.size();
};

pack::pack(){}
pack::pack(int num)
{
    ip.resize(num);
    tcp.resize(num);
    ethernet.resize(num);
    payload.resize(num);
    packets.resize(num);
    headers.resize(num);
//    for  (int i=0; i<num; i++)
//    {
//        const struct sniff_ip *temp_ip=new struct sniff_ip;
//        ip.push_back(temp_ip);

//        const sniff_ethernet *temp_ethernet=new sniff_ethernet;
//        ethernet.push_back(temp_ethernet);

//        const sniff_tcp *temp_tcp=new sniff_tcp;
//        tcp.push_back(temp_tcp);

//        struct pcap_pkthdr *temp_header=new struct pcap_pkthdr;
//        headers.push_back(temp_header);

//        u_char *temp_packet=new u_char[255] ;
//        packets.push_back(temp_packet);

//        u_char *temp_payload=new u_char[255];
//        payload.push_back(temp_payload);
//    }
}

pack::~pack()
{
    ip.clear();
    tcp.clear();
    payload.clear();
    ethernet.clear();
    headers.clear();
    packets.clear();
}

pack::pack(pack &temp)
{
    int num=temp.ip.size();
    ip.resize(num);
    tcp.resize(num);
    payload.resize(num);
    ethernet.resize(num);
    headers.resize(num);
    packets.resize(num);
    for (int i=0; i<num; i++)
    {
        ip[i]=temp.ip[i];
        tcp[i]=temp.tcp[i];
        payload[i]=temp.payload[i];
        ethernet[i]=temp.ethernet[i];
        headers[i]=temp.headers[i];
        packets[i]=temp.packets[i];
    }
}

pack &pack::operator = (pack &temp)
{
    if (this!=&temp)
    {
        int num=temp.ip.size();
        ip.resize(num);
        tcp.resize(num);
        payload.resize(num);
        ethernet.resize(num);
        headers.resize(num);
        packets.resize(num);
        for (int i=0; i<num; i++)
        {
            ip[i]=temp.ip[i];
            tcp[i]=temp.tcp[i];
            payload[i]=temp.payload[i];
            ethernet[i]=temp.ethernet[i];
            headers[i]=temp.headers[i];
            packets[i]=temp.packets[i];
        }
    }
    return *this;
}
