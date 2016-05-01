TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_CFLAGS += -std=c99 -pedantic -Wall -Wextra -Werror

SOURCES += main.c \
    communication.c \
    loging.c \
    oauth.c \
    cJson/cJSON.c

HEADERS += \
    communication.h \
    config.h \
    oauth.h \
    cJson/cJSON.h


unix: LIBS += -lcurl

win32: LIBS += -L "C:\Users\JustMe\Desktop\curl-7.40.0-devel-mingw32\lib" -lcurldll -lcurl

win32: LIBS += -L$$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/lib/ -lwsock32

win32: LIBS += -L$$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/lib/ -ladvapi32
