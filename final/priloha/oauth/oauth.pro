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

# edit curl lib destination
win32: LIBS += -L "E:\oauth_fin\curl\lib" -lcurldll -lcurl

# edit path to your compliler lib folder, lwsock32 and ladvapi32 are common libraries in windows environment
win32: LIBS += -lwsock32 -ladvapi32





