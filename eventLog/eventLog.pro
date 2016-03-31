TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_CFLAGS += -std=c99 -pedantic -Wall -Wextra -Wno-unknown-pragmas

SOURCES += main.c \
    loging.c
