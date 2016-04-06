TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    module.c \
    commons.c

LIBS += -lcurl -lxml2 -lcrypto -lssl
