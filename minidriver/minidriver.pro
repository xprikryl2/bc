TEMPLATE = lib

QMAKE_CFLAGS += -std=c99 -Wno-unknown-pragmas -Wall -Wunknown-pragmas

LIBS += -llibxml2 -llibeay32
LIBS += -L$$PWD/curl/lib/ -lcurl -lcurldll

SOURCES += \
    minidriver.c

HEADERS += \
    cardmod.h



