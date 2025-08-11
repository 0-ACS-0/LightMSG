#!/bin/bash


# Variables de entorno             #
# -------------------------------- #
CC=gcc
CFLAGS_TEST="-g -Wall -O2 -pthread -lssl -lcrypto"
CFLAGS_LIB="-Wall -O2 -fPIC -shared"

SRC_SERVER=server.c
INC_SERVER=server.h
SRC_TEST=test_server.c

TEST_PROG=test_server.elf
LIB_PROG=server.so
# -------------------------------- #


# Lógica de uso                    #
# -------------------------------- #
if [ "$1" == "test" ]; then
    echo
    echo "[BUILD-SERVER-TEST]: Compilando programa de prueba de servidor..."
    if $CC $CFLAGS_TEST $SRC_TEST $SRC_SERVER -o $TEST_PROG; then
        echo "[BUILD-SERVER-TEST]: Compilación completada."
        echo "[BUILD-SERVER-TEST]: Ejecutando programa de prueba..."
        echo
        ./$TEST_PROG
        echo
        echo "[BUILD-SERVER-TEST]: Ejecución de programa de prueba finalizado."
    else
        echo "[BUILD-SERVER-TEST][ERR]: Error de compilación, ejecución abortada."
    fi
    echo

elif [ "$1" == "lib" ]; then
    echo
    echo "[BUILD-SERVER-LIB]: Compilando la librería de server..."
    if $CC $CFLAGS_LIB $SRC_SERVER -o $LIB_PROG; then
        mv $LIB_PROG ./lib
        cp $INC_SERVER ./lib
        echo "[BUILD-SERVER-LIB]: Librearía compilada."
    else
        echo "[BUILD-SERVER-LIB][ERR]: Error de compilación, librería no generada."
    fi
    echo

elif [ "$1" == "clean" ]; then
    echo
    echo "[BUILD-SERVER-CLEAN]: Limpiando espacio de trabajo..."
    rm -f ./$TEST_PROG ./lib/* ./logs/*
    echo "[BUILD-SERVER-CLEAN]: Espacio de trabajo limpio."
    echo

else
    echo
    echo "[BUILD-SERVER][ERR]: Uso incorrecto u opciones inválidas."
    echo -e "\n\t[Uso]:"
    echo -e "\t\t-> ./build.sh test: \tCompila y ejecuta el programa de test (.elf)."
    echo -e "\t\t-> ./build.sh lib: \tCompila y genera la librería compartida (.so) bajo la carpeta lib/."
    echo -e "\t\t-> ./build.sh clean: \tLimpia el espacio de trabajo eliminando archivos generados (incluyendo los logs del servidor!)."
    echo
    exit 1
fi
# -------------------------------- #