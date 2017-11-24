#include "form.h"
#include "ui_form.h"

form::form(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::form)
{
    ui->setupUi(this);
}

form::~form()
{
    delete ui;
}
void form::append_in(QString string)
{
    ui->tb_in->append(string);
}

void form::append_out(QString string)
{
    ui->tb_out->append(string);
}
