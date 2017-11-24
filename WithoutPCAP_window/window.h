#ifndef WINDOW_H
#define WINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QTime>
#include <fstream>
#include "packet.h"
#include "form.h"
#include "pack.h"

namespace Ui {
class window;
}

class window : public QMainWindow
{
    Q_OBJECT
    QVector<packet> packets_temp;
    QVector<packet> packets;
public:
    form *wind_sort;
    pack *wind_search;
    explicit window(QWidget *parent = 0);
    ~window();

private:
    Ui::window *ui;

private slots:
    void sort();
    void search();
};

#endif // WINDOW_H
