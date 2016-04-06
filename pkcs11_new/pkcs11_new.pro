TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c


LIBS += -lcurl -lxml2 -lcrypto

