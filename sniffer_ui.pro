#-------------------------------------------------
#
# Project created by QtCreator 2014-10-10T09:33:30
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer_ui
TEMPLATE = app


SOURCES += main.cpp\
        sniffer_ui.cpp \
    my_sniffer.cpp \
    chose_dev.cpp \
    my_deal.cpp

HEADERS  += sniffer_ui.h \
    my_sniffer.h \
    Packet_Format.h \
    chose_dev.h \
    my_deal.h

FORMS    += sniffer_ui.ui \
    chose_dev.ui
LIBS += -lpcap

RESOURCES += \
    myicon.qrc
