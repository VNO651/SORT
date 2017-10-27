#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "array.h"


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    array *window;

private:
    Ui::MainWindow *ui;
private slots:
    void push();
};

#endif // MAINWINDOW_H
