#include "mainwindow.h"
#include <QApplication>

/*
#--------------------------------------------------------
#	AES Encrypted and AntiVM PE Builder (Crypter Generator)
#
#	https://www.github.com/hex4d0r/hCrypt
#
#	Coded by Hex4d0r for Educational Purposes
#--------------------------------------------------------
*/

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
