#ifndef ARRAY_H
#define ARRAY_H

#include <QWidget>
#include <QMainWindow>

namespace Ui {
class array;
}

class array : public QMainWindow
{
    Q_OBJECT

public:
    explicit array(QMainWindow *parent=0);
    ~array();
    void append_in(QString string);
    void append_out(QString string);
private:
    Ui::array *ui;
};

#endif // ARRAY_H
