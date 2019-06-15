#-------------------------------------------------
#
# Project created by QtCreator 2017-12-28T22:18:07
#
#-------------------------------------------------

#--------------------------------------------------------
#	AES Encrypted and AntiVM PE Builder (Crypter Generator)
#
#	https://www.github.com/hex4d0r/hCrypt
#
#	Coded by Hex4d0r for Educational Purposes
#--------------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = hCrypt
TEMPLATE = app

win32:RC_ICONS += Images/hCrypt.ico

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        Source/main.cpp \
        Source/mainwindow.cpp \
    Source/about.cpp \
    ThirdParty/VirtualAES/VirtualAES.cpp

HEADERS += \
        Header/mainwindow.h \
    Header/about.h \
    ThirdParty/VirtualAES/VirtualAES.h

FORMS += \
        Ui/mainwindow.ui \
    Ui/about.ui

RESOURCES += \
    res.qrc
