#ifndef PACK_H
#define PACK_H

#include <QWidget>

namespace Ui {
class pack;
}

class pack : public QWidget
{
    Q_OBJECT

public:
    void append_in(QString string);
    explicit pack(QWidget *parent = 0);
    ~pack();

private:
    Ui::pack *ui;
};

#endif // PACK_H
