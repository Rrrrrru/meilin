#!/bin/sh

source /koolshare/scripts/base.sh
eval `dbus export merlinclash`
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
mkdir -p /tmp/upload
LOG_FILE=/tmp/upload/merlinclash_log.txt
SIMLOG_FILE=/tmp/upload/merlinclash_simlog.txt
rm -rf $LOG_FILE
rm -rf $SIMLOG_FILE
echo "" > /tmp/upload/merlinclash_log.txt
echo "" > $SIMLOG_FILE
http_response "$1"

start_rebuild(){

	echo_date "重建yaml文件列表" >> $LOG_FILE
	find /koolshare/merlinclash/yaml_bak  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_bak/yamls.txt
	#创建软链接
	ln -sf /koolshare/merlinclash/yaml_bak/yamls.txt /tmp/upload/yamls.txt
	#
	echo_date "重建host文件列表" >> $LOG_FILE
	find /koolshare/merlinclash/yaml_basic/host  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_basic/host/hosts.txt
	#创建软链接
	ln -sf /koolshare/merlinclash/yaml_basic/host/hosts.txt /tmp/upload/hosts.txt

	echo_date "下拉列表重建完成" >> $LOG_FILE
}

case $2 in
rebuild)
	start_rebuild
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	;;
esac