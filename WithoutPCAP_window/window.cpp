#include "window.h"
#include "ui_window.h"
#include <QVector>
#include <fstream>

bool check (unsigned char* buf);
void protocol (int num);
void sort_bubble(QVector<packet> &vec, int num);
void sort_hoar(QVector<packet> &vec, int left, int right);
void sort_merge(QVector<packet> &vec, int left, int right, int num);
int search_simple(QVector<packet> vec, ip_address temp);
int search_binary (QVector<packet> vec, int left, int right, ip_address key);

window::window(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::window)
{
    ui->setupUi(this);
    move(200, 200);
    connect(ui->pb_sort, SIGNAL(clicked(bool)), this, SLOT(sort()));
}

window::~window()
{
    delete ui;
}

void window::sort()
{
    unsigned char *buf=new unsigned char[4];
    unsigned char *temp_ch=new unsigned char;
    std::fstream file;
    QString path;
    if (ui->le_pcap->text().isEmpty())
        return;
    path=ui->le_pcap->text();
    file.open(path.toStdString().c_str(), std::ios::binary|std::ios::in );
    if (!file.is_open())
    {
        return;
    }
    file.read((char*)buf, 3);

    int count=0;
    while (file.gcount()>0)
    {
        bool ret=check(buf);
        if (ret==true)
        {
            packets.resize(count+1);
            file.read((char*)temp_ch, 1);
            int temp=static_cast<int>(*temp_ch);
            packets[count].service.priority=temp>>5;
            packets[count].service.delay=temp&16;
            packets[count].service.throughput=temp&8;
            packets[count].service.reliability=temp&4;
            packets[count].service.ECN=temp&3;

            file.read((char*)buf, 2);
            int x=static_cast<int>(buf[0]);
            int y=static_cast<int>(buf[1]);
            x=x*256+y;
            packets[count].total_len=x;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].identification=temp;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].flag.reserved=temp&32768;
            packets[count].flag.fragment=temp&16384;
            packets[count].flag.more_fragments=temp&8192;
            packets[count].fragment_offset=temp&8191;

            file.read((char*)buf, 2);
            temp=static_cast<int>(buf[0]);
            packets[count].ttl=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].protocol=temp;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].checksum=temp;

            file.read((char*)buf, 4);
            temp=static_cast<int>(buf[0]);
            packets[count].sourse.x1=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].sourse.x2=temp;
            temp=static_cast<int>(buf[2]);
            packets[count].sourse.x3=temp;
            temp=static_cast<int>(buf[3]);
            packets[count].sourse.x4=temp;

            file.read((char*)buf, 4);
            temp=static_cast<int>(buf[0]);
            packets[count].destination.x1=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].destination.x2=temp;
            temp=static_cast<int>(buf[2]);
            packets[count].destination.x3=temp;
            temp=static_cast<int>(buf[3]);
            packets[count].destination.x4=temp;
            count++;
        }
        else
        {
            file.seekg(-2, std::ios::cur);
            file.read((char*)buf, 3);
        }
    }
    file.close();
    ui->lb->setText("Found packets: "+QString::number(count));
    update();
    wind_sort=new form;
    for (int i=0; i<packets.size(); i++)
    {
        wind_sort->append_in("Packet " + QString::number(i+1)
                             + ":\n" + packets[i].out() + "\n");
    }

    packets_temp=packets;
    QTime timer_bubble;
    timer_bubble.start();
    sort_bubble(packets_temp,packets_temp.size());
    int time_bubble=timer_bubble.elapsed();
    ui->lcd_bubble->display(time_bubble);


    packets_temp=packets;
    QTime timer_hoar;
    timer_hoar.start();
    sort_hoar(packets_temp, 0, packets_temp.size()-1);
    int time_hoar=timer_hoar.elapsed();
    ui->lcd_hoar->display(time_hoar);

    packets_temp=packets;
    QTime timer_merge;
    timer_merge.start();
    sort_merge(packets_temp, 0, packets_temp.size()-1, packets_temp.size());
    int time_merge=timer_merge.elapsed();
    ui->lcd_merge->display(time_merge);
    packets_temp=packets;
    QTime timer_sort;
    timer_sort.start();
    std::sort(packets_temp.begin(), packets_temp.end());
    int time_sort=timer_sort.elapsed();
    ui->lcd_sort->display(time_sort);
    for (int i=0; i<packets_temp.size(); i++)
    {
        wind_sort->append_out("Packet " + QString::number(i+1)
                              + ":\n" + packets_temp[i].out() + "\n");
    }
    wind_sort->move(200+this->width(), 200);
    wind_sort->show();

    connect(ui->pb_search, SIGNAL(clicked(bool)), this, SLOT(search()));

    delete[] buf;
    delete temp_ch;
    return;
}

void window::search()
{
    wind_search=new pack;
    ip_address temp;
    if (ui->le_x1->text().isEmpty()) return;
    temp.x1=ui->le_x1->text().toInt();
    if (ui->le_x2->text().isEmpty()) return;
    temp.x2=ui->le_x2->text().toInt();
    if (ui->le_x3->text().isEmpty()) return;
    temp.x3=ui->le_x3->text().toInt();
    if (ui->le_x4->text().isEmpty()) return;
    temp.x4=ui->le_x4->text().toInt();

    QTime timer_simple;
    timer_simple.start();
    int number=search_simple(packets, temp);
    int time_simple=timer_simple.elapsed()+1;
    ui->lcd_simple->display(time_simple);

    QTime timer_binary;
    timer_binary.start();
    int number_bin=search_binary(packets_temp, 0, packets_temp.size(), temp);
    int time_binary=timer_binary.elapsed();
    ui->lcd_binary->display(time_binary);
    wind_search->append_in("Packet " + QString::number(number_bin+1)
                           + ":\n" + packets_temp[number_bin].out());
    wind_search->move(793+wind_sort->width(), 200);
    wind_search->show();
    return;
}

bool check (unsigned char *buf)
{
    int x=static_cast<int>(buf[2]);
    x=x>>4;
    QString temp;
    int arr[3];
    for (int i=0; i<3; i++)
        arr[i]=static_cast<int>(buf[i]);
    for (int i=0; i<2; i++)
    {
        if (arr[i]<10)
        {
            if (arr[i]==0)
                temp.append("00");
            else
            {
                temp.append('0');
                temp.append(QString::number(arr[i], 16));
            }
        }
        else
            temp.append(QString::number(arr[i], 16));
    }
    temp.append(QString::number(x, 16));
    if (temp=="08004")
    {
        return true;
    }
    else
    {
        return false;
    }
}
void sort_bubble(QVector<packet> &vec, int num)
{
    for (int i=0; i<num-1; i++)
        for (int j=0; j<num-i-1; j++)
            if (vec[j+1]<vec[j])
                std::swap(vec[j], vec[j+1]);
}
void sort_hoar(QVector<packet> &vec, int left, int right)
{
    int i=left;
    int j=right;
    int mid=(left+right+1)/2;
    do
    {
        while (vec[i]<vec[mid])
            i++;
        while (vec[mid]<vec[j])
            j--;
        if (i<=j)
        {
            if (i<j) std::swap(vec[i], vec[j]);
            i++;
            j--;
        }
    } while (i<=j);
    if (i<right) sort_hoar(vec, i, right);
    if (j>left) sort_hoar(vec, left, j);
}
void sort_merge (QVector<packet> &vec, int left, int right, int num)
{
    if (left==right) return;
    if (right-left==1)
    {
        if (vec[right]<vec[left])
            std::swap (vec[left], vec[right]);
        return;
    }
    int mid = (left+right)/2;
    sort_merge(vec, left, mid, num);
    sort_merge(vec, mid+1, right, num);

    QVector<packet> vec_temp;
    vec_temp=vec;
    int _left=left;
    int _right=mid+1;
    int cur=0;

    while (right-left+1 != cur)
    {
        if (_left>mid)
        {
            vec_temp[cur]=vec[_right];
            cur++; _right++;
        }
        else if (_right>right)
        {
            vec_temp[cur]=vec[_left];
            cur++; _left++;
        }
        else if (vec[_right]<vec[_left])
        {
            vec_temp[cur]=vec[_right];
            cur++; _right++;
        }
        else
        {
            vec_temp[cur]=vec[_left];
            cur++; _left++;
        }
    }
    for (int i=0; i<cur; i++)
        vec[i+left]=vec_temp[i];
}
int search_simple(QVector<packet> vec, ip_address temp)
{
    for (int i=0; i<vec.size(); i++)
        if (vec[i].destination==temp)
            return i;
    return -1;
}
int search_binary (QVector<packet> vec, int left, int right, ip_address key)
{
    int midd = 0;
    while (1)
    {
        midd = (left + right) / 2;

        if (key < vec[midd].destination)       // если искомое меньше значения в ячейке
            right = midd - 1;      // смещаем правую границу поиска
        else if (vec[midd].destination < key )  // если искомое больше значения в ячейке
            left = midd + 1;	   // смещаем левую границу поиска
        else                       // иначе (значения равны)
            return midd;           // функция возвращает индекс ячейки

        if (left > right)          // если границы сомкнулись
            return -1;
    }
}




