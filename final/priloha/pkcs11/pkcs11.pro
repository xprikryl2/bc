TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CFLAGS += -Wall -Wextra
win32: QMAKE_CFLAGS += -std=c99

SOURCES += main.c \
    pkcs11.c

unix:!macx: LIBS += -lcurl -lxml2 -lcrypto

win32: LIBS += -llibxml2 -llibeay32  -lcurldll -lcurl

HEADERS += \
    config.h

