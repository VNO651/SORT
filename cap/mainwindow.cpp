#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <pcap.h>
#include "pack.h"
#include <winsock2.h>
#include <windows.h>
#include <cstring>
#include <QTime>
#include <stdio.h>
#include <time.h>
#include <fstream>


#define mNum 2000
void swap(pack &p, int i, int j);
void change(pack &p, pack &two, int i, int j);
void sort_bubble(pack &p, int num);
void sort_hoar(pack &arr, int left, int right);
void sort_merge(pack &arr, int left, int right, int num);

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    move(200, 200);
    connect(ui->pb, SIGNAL(clicked()), this, SLOT(push()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::push()
{
    int x=595;
    int y=315;
    //кодировка windows-1251/CP1251
    pack p;
    pack p_temp;
    system ("chcp 1251");
    system("cls");
    setlocale(LC_ALL, "Russian");
    char errbuf[PCAP_ERRBUF_SIZE];

    char *path=new char[CHAR_MAX];
    QString Qpath=ui->le_pcap->text();
    //  D://Varakin/cap/example.cap
//    Qpath+="D://Varakin/cap/example.cap";
    if (Qpath.isEmpty()==true) return;
    strcpy(path, Qpath.toStdString().c_str());
    update();

    pcap_t *pcap;
    pcap=pcap_open_offline(path, errbuf);
    if (pcap==0)
    {
        //cout<<"Ошибка pcap_open_offline: "<<errbuf<<endl;
        return ;
    }
    bpf_program filter;
    bpf_u_int32 net=0;
    char filter_app[] = "";
    if ( pcap_compile(pcap, &filter, filter_app, 0, net)==-1)
    { return ; }
    pcap_setfilter(pcap, &filter);
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);
    int i=0;
    int num=0;
    p.headers.clear();
    p.ip.clear();
    p.tcp.clear();
    p.ethernet.clear();
    p.packets.clear();
    p.payload.clear();
    struct pcap_pkthdr *hdr;
    const u_char *packet;

    window=new array;
    char *buf=new char[255];
    int count=0;
    QString string;
    if (ui->le_num->text()=="" ||
            ui->le_num->text()=="full" || ui->le_num->text()=="0")
        while ( pcap_next_ex(pcap, &hdr, &packet)>=0)
        {
            p.headers.push_back(new pcap_pkthdr);
            *p.headers[i]=*hdr;
            p.packets.push_back(new u_char[p.headers[i]->len]);
            for (unsigned int j=0; j<p.headers[i]->len; j++)
                p.packets[i][j]=packet[j];
            p.ethernet.push_back((struct sniff_ethernet*)(p.packets[i]));
            p.ip.push_back((struct sniff_ip*)(p.packets[i] + size_ethernet));
            p.tcp.push_back((struct sniff_tcp*)(p.packets[i] + size_ethernet + size_ip));
            p.payload.push_back((u_char *)(p.packets[i]+size_ethernet+size_ip+size_tcp));
            char source[30];
            strcpy(source,inet_ntoa(p.ip[i]->ip_src));
            char destination[30];
            strcpy(destination,inet_ntoa(p.ip[i]->ip_dst));
            sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                         "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                         "Порт отправителя: %4u\nПорт получателя: %4u\n"
                         "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\n\n",
                    i+1, p.headers[i]->ts.tv_sec, p.headers[i]->ts.tv_usec,
                    p.headers[i]->len, p.headers[i]->caplen, p.tcp[i]->th_sport,
                    p.tcp[i]->th_dport, source, destination, p.ip[i]->ip_ttl);
            string+=buf;
            i++;
        }
    else
    {
        count=ui->le_num->text().toInt();
        while ( pcap_next_ex(pcap, &hdr, &packet)>=0 && i<count)
        {
            p.headers.push_back(new pcap_pkthdr);
            *p.headers[i]=*hdr;
            p.packets.push_back(new u_char[p.headers[i]->len]);
            for (unsigned int j=0; j<p.headers[i]->len; j++)
                p.packets[i][j]=packet[j];
            p.ethernet.push_back((struct sniff_ethernet*)(p.packets[i]));
            p.ip.push_back((struct sniff_ip*)(p.packets[i] + size_ethernet));
            p.tcp.push_back((struct sniff_tcp*)(p.packets[i] + size_ethernet + size_ip));
            p.payload.push_back((u_char *)(p.packets[i]+size_ethernet+size_ip+size_tcp));
            char source[30];
            strcpy(source,inet_ntoa(p.ip[i]->ip_src));
            char destination[30];
            strcpy(destination,inet_ntoa(p.ip[i]->ip_dst));
            sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                         "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                         "Порт отправителя: %4u\nПорт получателя: %4u\n"
                         "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\n\n",
                    i+1, p.headers[i]->ts.tv_sec, p.headers[i]->ts.tv_usec,
                    p.headers[i]->len, p.headers[i]->caplen, p.tcp[i]->th_sport,
                    p.tcp[i]->th_dport, source, destination, p.ip[i]->ip_ttl);
            string+=buf;
            i++;
        }
    }
    window->append_in(string);
    window->update();
    window->move(791, 200);
    window->show();

    num=i;
    p.headers.resize(num);
    p.ip.resize(num);
    p.tcp.resize(num);
    p.ethernet.resize(num);
    p.payload.resize(num);
    p.packets.resize(num);
    p_temp=p;

    int time_bubble;
    QTime timer_bubble;
    timer_bubble.start();
    sort_bubble(p_temp, num);
    time_bubble=timer_bubble.elapsed();
    ui->lcd_bubble->display(QString::number(time_bubble));
//    ui->label_bubble->show();

    p_temp=p;
    int time_hoar;
    QTime timer_hoar;
    timer_hoar.start();
    sort_hoar(p_temp, 0, num-1);
    time_hoar=timer_hoar.elapsed();
    ui->lcd_hoar->display(QString::number(time_hoar));
//    ui->label_hoar->show();

    QString string_sort;
    for (i=0; i<num; i++)
    {
        char source[30];
        strcpy(source,inet_ntoa(p_temp.ip[i]->ip_src));
        char destination[30];
        strcpy(destination,inet_ntoa(p_temp.ip[i]->ip_dst));
        sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                     "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                     "Порт отправителя: %4u\nПорт получателя: %4u\n"
                     "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\t\n\n",
                i+1, p_temp.headers[i]->ts.tv_sec, p_temp.headers[i]->ts.tv_usec,
                p_temp.headers[i]->len, p_temp.headers[i]->caplen,
                p_temp.tcp[i]->th_sport, p_temp.tcp[i]->th_dport,
                source, destination, p_temp.ip[i]->ip_ttl);
        string_sort+=buf;
    }
    window->append_out(string_sort);
    window->update();

    p_temp=p;
    int time_merge;
    QTime timer_merge;
    timer_merge.start();
    sort_merge(p_temp, 0, num-1, num);
    time_merge=timer_merge.elapsed();
    ui->lcd_mege->display(QString::number(time_merge));
//    ui->label_merge->show();

    int time_sort=(time_hoar+time_merge)/2;
    ui->lcd_sort->display(QString::number(time_sort));
//    ui->label_sort->show();

    pcap_close(pcap);
}

void sort_bubble(pack &p, int num)
{
    for (int i=0; i<num-1; i++)
        for (int j=0; j<num-i-1; j++)
            if (p.ip[j]->ip_ttl>p.ip[j+1]->ip_ttl)
                swap(p, j, j+1);
}
void sort_hoar(pack &arr, int left, int right)
{
    int i=left;
    int j=right;
    int middle=(left+right+1)/2;
    do
    {
        while(arr.ip[i]->ip_ttl<arr.ip[middle]->ip_ttl) i++;
        while(arr.ip[j]->ip_ttl>arr.ip[middle]->ip_ttl) j--;
        if (i<=j)
        {
            swap(arr, i, j);
            i++;
            j--;
        }
    } while (i<=j);
    if (i<right) sort_hoar(arr, i, right);
    if (left<j) sort_hoar(arr, left, j);
}
void sort_merge (pack &arr, int left, int right, int num)
{
    if (left==right) return;
    if (right-left==1)
    {
        if (arr.ip[left]->ip_ttl>arr.ip[right]->ip_ttl)
            swap(arr, left, right);
        return;
    }
    int mid=(left+right)/2;
    sort_merge(arr, left, mid, num);
    sort_merge(arr, mid+1, right, num);

    pack arr_temp;
    arr_temp.ip.resize(num);
    arr_temp.ethernet.resize(num);
    arr_temp.headers.resize(num);
    arr_temp.packets.resize(num);
    arr_temp.tcp.resize(num);
    arr_temp.payload.resize(num);

    int _left=left;
    int _right=mid+1;
    int cur=0;
    while (right-left+1 != cur)
    {
        if (_left>mid)
        {
            arr_temp.ip[cur]=arr.ip[_right];
            arr_temp.tcp[cur]=arr.tcp[_right];
            arr_temp.ethernet[cur]=arr.ethernet[_right];
            arr_temp.headers[cur]=arr.headers[_right];
            arr_temp.packets[cur]=arr.packets[_right];
            arr_temp.payload[cur]=arr.payload[_right];
            cur++; _right++;
        }
        else if (_right>right)
        {
            arr_temp.ip[cur]=arr.ip[_left];
            arr_temp.tcp[cur]=arr.tcp[_left];
            arr_temp.ethernet[cur]=arr.ethernet[_left];
            arr_temp.headers[cur]=arr.headers[_left];
            arr_temp.packets[cur]=arr.packets[_left];
            arr_temp.payload[cur]=arr.payload[_left];
            cur++; _left++;
        }
        else if (arr.ip[_left]->ip_ttl>arr.ip[_right]->ip_ttl)
        {
            arr_temp.ip[cur]=arr.ip[_right];
            arr_temp.tcp[cur]=arr.tcp[_right];
            arr_temp.ethernet[cur]=arr.ethernet[_right];
            arr_temp.headers[cur]=arr.headers[_right];
            arr_temp.packets[cur]=arr.packets[_right];
            arr_temp.payload[cur]=arr.payload[_right];
            cur++; _right++;
        }
        else
        {
            arr_temp.ip[cur]=arr.ip[_left];
            arr_temp.tcp[cur]=arr.tcp[_left];
            arr_temp.ethernet[cur]=arr.ethernet[_left];
            arr_temp.headers[cur]=arr.headers[_left];
            arr_temp.packets[cur]=arr.packets[_left];
            arr_temp.payload[cur]=arr.payload[_left];
            cur++; _left++;
        }
    }
    for (int i=0; i<cur; i++)
    {
        arr.ip[i+left]=arr_temp.ip[i];
        arr.tcp[i+left]=arr_temp.tcp[i];
        arr.ethernet[i+left]=arr_temp.ethernet[i];
        arr.headers[i+left]=arr_temp.headers[i];
        arr.packets[i+left]=arr_temp.packets[i];
        arr.payload[i+left]=arr_temp.payload[i];
    }
}

void swap(pack &p, int i, int j)
{
    const sniff_ethernet *temp_ethernet=p.ethernet[i];
    const sniff_ip *temp_ip=p.ip[i];
    const sniff_tcp *temp_tcp=p.tcp[i];
    struct pcap_pkthdr *temp_header=p.headers[i];
    u_char *temp_packet=p.packets[i];
    u_char* temp_payload=p.payload[i];

    p.ip[i]=p.ip[j];
    p.ip[j]=temp_ip;

    p.tcp[i]=p.tcp[j];
    p.tcp[j]=temp_tcp;

    p.ethernet[i]=p.ethernet[j];
    p.ethernet[j]=temp_ethernet;

    p.headers[i]=p.headers[j];
    p.headers[j]=temp_header;

    p.packets[i]=p.packets[j];
    p.packets[j]=temp_packet;

    p.payload[i]=p.payload[j];
    p.payload[j]=temp_payload;
}
