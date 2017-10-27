#include "array.h"
#include "ui_array.h"

array::array(QMainWindow *parent) :
    QMainWindow(parent),
    ui(new Ui::array)
{
    ui->setupUi(this);
}

array::~array()
{
    delete ui;
}

void array::append_in(QString string)
{
    ui->tb_in->append(string);
}

void array::append_out(QString string)
{
    ui->tb_out->append(string);
}

