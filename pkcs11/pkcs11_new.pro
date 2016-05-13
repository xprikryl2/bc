TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CFLAGS += -Wall -Wextra
win32: QMAKE_CFLAGS += -std=c99

SOURCES += main.c \
    pkcs11.c


unix:!macx: LIBS += -lcurl -lxml2 -lcrypto

win32: LIBS += -L$$PWD/../../../../../../Qt/Tools/MinGW/i686-w64-mingw32/lib/ -llibxml2 -llibeay32
win32: LIBS += -L "C:\Users\JustMe\Desktop\curl-7.40.0-devel-mingw32\lib" -lcurldll -lcurl

HEADERS += \
    config.h

