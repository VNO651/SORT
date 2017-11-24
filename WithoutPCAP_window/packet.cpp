#include "packet.h"
QString protocol_decode (int num);
packet::packet()
{
    checksum=0;
    fragment_offset=0;
    ttl=0;
    identification=0;
    total_len=0;
    protocol=0;
    flag.fragment=0;
    flag.more_fragments=0;
    flag.reserved=0;
    service.delay=0;
    service.ECN=0;
    service.priority=0;
    service.reliability=0;
    service.throughput=0;
    destination.x1=0;
    destination.x2=0;
    destination.x3=0;
    destination.x4=0;
    sourse.x1=0;
    sourse.x2=0;
    sourse.x3=0;
    sourse.x4=0;
}
packet::~packet()
{
    this->checksum=0;
    this->fragment_offset=0;
    this->ttl=0;
    this->identification=0;
    this->total_len=0;
    this->protocol=0;
    this->flag.fragment=0;
    this->flag.more_fragments=0;
    this->flag.reserved=0;
    this->service.delay=0;
    this->service.ECN=0;
    this->service.priority=0;
    this->service.reliability=0;
    this->service.throughput=0;
    this->destination.x1=0;
    this->destination.x2=0;
    this->destination.x3=0;
    this->destination.x4=0;
    this->sourse.x1=0;
    this->sourse.x2=0;
    this->sourse.x3=0;
    this->sourse.x4=0;
}
packet::packet(const packet &temp)
{
    service=temp.service;
    flag=temp.flag;
    sourse=temp.sourse;
    destination=temp.destination;
    total_len=temp.total_len;
    identification=temp.identification;
    fragment_offset=temp.fragment_offset;
    ttl=temp.ttl;
    protocol=temp.protocol;
    checksum=temp.protocol;
}
packet& packet::operator = (const packet &temp)
{
    if (this!=&temp)
    {
        service=temp.service;
        flag=temp.flag;
        sourse=temp.sourse;
        destination=temp.destination;
        total_len=temp.total_len;
        identification=temp.identification;
        fragment_offset=temp.fragment_offset;
        ttl=temp.ttl;
        protocol=temp.protocol;
        checksum=temp.protocol;
    }
    return *this;
}
bool packet::operator < (const packet& temp)
{
    if (destination.x1!=temp.destination.x1)
        return destination.x1<temp.destination.x1;
    else
        if (destination.x2!=temp.destination.x2)
            return destination.x2!=temp.destination.x2;
        else
            if (destination.x3!=temp.destination.x3)
                return destination.x3<temp.destination.x3;
            else
                    return destination.x4<temp.destination.x4;
}
bool packet::operator == (const packet& temp)
{
    if (service.delay==temp.service.delay &&
            service.ECN==temp.service.ECN &&
            service.priority==temp.service.priority &&
            service.reliability==temp.service.reliability &&
            service.throughput==temp.service.throughput &&
            flag.fragment==temp.flag.fragment &&
            flag.more_fragments==temp.flag.more_fragments &&
            flag.reserved==temp.flag.reserved &&
            sourse==temp.sourse &&
            destination==temp.destination &&
            total_len==temp.total_len &&
            identification==temp.identification &&
            fragment_offset==temp.fragment_offset &&
            ttl==temp.ttl &&
            protocol==temp.protocol &&
            checksum==temp.protocol)
        return true;
    else
        return false;
}
QString packet::out()
{
    QString str;
    str+="Services:\n";
    str+="Priority: ";
    str+=QString::number(service.priority);
    str+='\n';
    if (service.delay==0)
        str+="  Delay: 0 - normal\n";
    else str+="  Delay: 1 - low\n";
    if (service.throughput==0)
        str+="  Throughput: 0 - low\n";
    else str+="  Throughput: 1 - high\n";
    if (service.reliability==0)
        str+="  Reliability: 0 - normal\n";
    else str+="  Reliability: 1 - high\n";
    if (service.ECN==0)
        str+="  Explicit Congestion Notification: 0 - Not ECN-Capable Transport\n";
    else str+="  Explicit Congestion Notification: 1 - Yes\n";
    str+="Total lenght: ";
    str+=QString::number(total_len);
    str+='\n';
    str+="Identification: 0x";
    str+=QString::number(identification, 16);
    str+=" (";
    str+=QString::number(identification, 10);
    str+=')';
    str+='\n';
    str+="Flags:\n";
    if (flag.reserved==0)
        str+="  Reserved: false\n";
    else str+="  Reserved: true\n";
    if (flag.fragment==0)
        str+="  Do not fragment: false\n";
    else str+="  Do not fragment: true\n";
    if (flag.more_fragments==0)
        str+="  More fragments: false\n";
    else str+="  More fragments: true\n";
    str+="Fragment Offset: ";
    str+=QString::number(fragment_offset);
    str+='\n';
    str+="TTL: ";
    str+=QString::number(ttl);
    str+='\n';
    str+="Protocol: ";
    str+=protocol_decode(protocol);
    str+='\n';
    str+="Header checksum: 0x";
    str+=QString::number(checksum, 16);
    str+='\n';
    str+="Source: ";
    str+=source_string();
    str+='\n';
    str+="Destination: ";
    str+=destination_string();
    str+='\n';
    return str;
}
QString protocol_decode (int num)
{
    switch (num)
    {
    case 1:
        return "ICMP";
    case 2:
        return "IGMP";
    case 3:
        return "IPv4";
    case 4:
        return "IGMP";
    case 5:
        return "ST";
    case 6:
        return "TCP";
    case 7:
        return "CBT";
    case 9:
        return "IGP";
    case 10:
        return "BBN-RCC-MON";
    case 11:
        return "NVP-II";
    case 12:
        return "PUP";
    case 13:
        return "ARGUS";
    case 14:
        return "EMCON";
    case 15:
        return "XNET";
    case 16:
        return "CHAOS";
    case 17:
        return "UDP";
    case 18:
        return "MUX";
        break;
    case 19:
        return "DCN-MEAS";
    case 20:
        return "HMP";
    case 21:
        return "PRM";
    case 27:
        return "RDP";
    case 33:
        return "DCCP";
        break;
    case 54:
        return "NARP";
    case 121:
        return "SMP";
    default:
        return "It is too lazy to know them all";
    }
}
QString packet::source_string()
{
    QString full_str=QString::number(sourse.x1)+'.'+
            QString::number(sourse.x2)+'.'+
            QString::number(sourse.x3)+'.'+
            QString::number(sourse.x4);
    return full_str;
}
QString packet::destination_string()
{
    QString full_str=QString::number(destination.x1)+'.'+
            QString::number(destination.x2)+'.'+
            QString::number(destination.x3)+'.'+
            QString::number(destination.x4);
    return full_str;
}
