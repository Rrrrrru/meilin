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

get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}

mcenable=$(get merlinclash_enable)
mkenable=$(get merlinclash_koolproxy_enable)


case $2 in
start)
	if [ "$mcenable" == "1" ];then
		echo start >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/merlinclash/clashconfig.sh restart >> /tmp/upload/merlinclash_log.txt
	else
		#echo stop >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/merlinclash/clashconfig.sh stop >> /tmp/upload/merlinclash_log.txt
	fi

	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	echo BBABBBBC >> $SIMLOG_FILE
	;;
upload)
	#echo upload >> /tmp/upload/merlinclash_log.txt
	sh /koolshare/merlinclash/clashconfig.sh upload
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	;;
update)
	#echo update >> /tmp/upload/merlinclash_log.txt
	sh /koolshare/merlinclash/clash_update_ipdb.sh
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	
	;;
quicklyrestart)
	if [ "$mcenable" == "1" ];then
		echo "快速重启" >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/merlinclash/clashconfig.sh quicklyrestart >> /tmp/upload/merlinclash_log.txt
	else
		echo "请先启用merlinclash" >> /tmp/upload/merlinclash_log.txt		
	fi
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	echo BBABBBBC >> $SIMLOG_FILE
	;;
iptquicklyrestart)
	if [ "$mcenable" == "1" ];then
		echo "重建iptables" >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/merlinclash/clashconfig.sh start_nat >> /tmp/upload/merlinclash_log.txt
	else
		echo "请先启用merlinclash" >> /tmp/upload/merlinclash_log.txt		
	fi
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	echo BBABBBBC >> $SIMLOG_FILE
	;;
unblockmusicrestart)
	if [ "$mcenable" == "1" ];then
		echo "网易云音乐解锁快速重启" >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/scripts/clash_unblockneteasemusic.sh restart
	else
		echo "请先启用merlinclash" >> /tmp/upload/merlinclash_log.txt		
	fi
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	;;
koolproxyrestart)
	if [ "$mcenable" == "1" ] && [ "$mkenable" == "1" ];then
		echo "KoolProxy重启" >> /tmp/upload/merlinclash_log.txt
		sh /koolshare/scripts/clash_koolproxyconfig.sh restart
	else
		if [ "$mcenable" != "1" ]; then
			echo "请先启用merlinclash" >> /tmp/upload/merlinclash_log.txt	
		fi
		if [ "$mkenable" != "1" ]; then
			echo "请先启用koolproxy" >> /tmp/upload/merlinclash_log.txt	
		fi	
	fi
	echo BBABBBBC >> /tmp/upload/merlinclash_log.txt
	;;
esac