#ifndef FORM_H
#define FORM_H

#include <QWidget>

namespace Ui {
class form;
}

class form : public QWidget
{
    Q_OBJECT

public:
    void append_in(QString string);
    void append_out(QString string);
    explicit form(QWidget *parent = 0);
    ~form();

private:
    Ui::form *ui;
};

#endif // FORM_H
