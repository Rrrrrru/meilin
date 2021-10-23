#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
#
ln -sf /koolshare/merlinclash/yaml_bak/yamls.txt /tmp/upload/yamls.txt
ln -sf /koolshare/merlinclash/yaml_bak/yamlscus.txt /tmp/upload/yamlscus.txt
ln -sf /koolshare/merlinclash/yaml_bak/yamlscuslist.txt /tmp/upload/yamlscuslist.txt
http_response $1

