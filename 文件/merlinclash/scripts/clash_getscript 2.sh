#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
#

ln -sf /koolshare/merlinclash/yaml_basic/script.yaml /tmp/upload/clash_script.txt

http_response $1

