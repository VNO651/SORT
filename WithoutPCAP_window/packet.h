#ifndef PACKET_H
#define PACKET_H
#include <string>
#include <QString>

struct service_type
{
public:
    unsigned int priority;
    unsigned int delay;
    unsigned int throughput;
    unsigned int reliability;
    unsigned int ECN;
    bool operator ==(const service_type& temp)
    {
        return (delay==temp.delay &&
                    ECN==temp.ECN &&
                    priority==temp.priority &&
                    reliability==temp.reliability &&
                    throughput==temp.throughput);
    }
};

struct flags
{
public:
    unsigned int reserved;
    unsigned int fragment;
    unsigned int more_fragments;
    bool operator == (const flags& temp)
    {
        return (reserved==temp.reserved &&
                fragment==temp.fragment &&
                more_fragments==temp.more_fragments);
    }
};

struct ip_address
{
public:
    unsigned int x1;
    unsigned int x2;
    unsigned int x3;
    unsigned int x4;
    bool operator < (const ip_address& temp)
    {
        if (x1!=temp.x1)
            return x1<temp.x1;
        else
            if (x2!=temp.x2)
                return x2!=temp.x2;
            else
                if (x3!=temp.x3)
                    return x3<temp.x3;
                else return x4<temp.x4;
    }
    bool operator == (const ip_address& temp)
    {
        return (x1==temp.x1 && x2==temp.x2
                && x3==temp.x3 && x4==temp.x4);
    }
};

class packet
{
public:
    service_type service;
    flags flag;
    ip_address sourse;
    ip_address destination;
    unsigned int total_len;
    unsigned int identification;
    unsigned int fragment_offset;
    unsigned int ttl;
    unsigned int protocol;
    unsigned int checksum;
    QString source_string();
    QString destination_string();
    QString out();
    packet();
    packet(const packet& temp);
    ~packet();
    packet& operator = (const packet& temp);
    bool operator < (const packet& temp);
    bool operator == (const packet& temp);
};

#endif // PACKET_H
