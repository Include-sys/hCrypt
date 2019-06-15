#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>
#include <QFileDialog>
#include <QDataStream>
#include <QDebug>
#include <iostream>
#include "about.h"
#include "VirtualAES/VirtualAES.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_f_open_clicked();

    void on_btn_build_clicked();

    void on_actionAbout_triggered();

private:
    Ui::MainWindow *ui; 
    struct toCrypt
    {
        char *rawData = nullptr;
        char test;
    };
    toCrypt data;
    qint64 size;

    About *mAbout;

public:
    void encrypt(char* rawData);
};

#endif // MAINWINDOW_H
