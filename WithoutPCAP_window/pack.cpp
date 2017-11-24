#include "pack.h"
#include "ui_pack.h"

pack::pack(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::pack)
{
    ui->setupUi(this);
}

pack::~pack()
{
    delete ui;
}

void pack::append_in(QString string)
{
    ui->tb_in->append(string);
}
