#!/bin/sh

echo Configuring with: $KEEPALIVED_CONFIG_ARGS

./configure $KEEPALIVED_CONFIG_ARGS || {
    cat config.log
    exit 1
}

make
