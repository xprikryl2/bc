TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_CFLAGS += -std=c99 -pedantic -Wall -Wextra -static-libgcc -static-libstdc++ -static
SOURCES += main.c \
    oauth.c \
    cJSON.c \
    communication.c \
    server.c \
    loging.c

HEADERS += \
    oauth.h \
    cJSON.h \
    communication.h

unix:!macx: LIBS += -lcurl

win32: LIBS += -L "C:\Users\JustMe\Desktop\curl-7.40.0-devel-mingw32\lib" -lcurldll -lcurl

win32: LIBS += -L$$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/lib/ -lwsock32

win32: INCLUDEPATH += $$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/include
win32: DEPENDPATH += $$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/include

win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/lib/wsock32.lib
else:win32-g++: PRE_TARGETDEPS += $$PWD/../../../../../../Qt/Tools/mingw491_32/i686-w64-mingw32/lib/libwsock32.a


