#!/bin/sh

prefix=/home/xingw/install_resicv/jemelloc
exec_prefix=/home/xingw/install_resicv/jemelloc
libdir=${exec_prefix}/lib

LD_PRELOAD=${libdir}/libjemalloc.so.2
export LD_PRELOAD
exec "$@"
