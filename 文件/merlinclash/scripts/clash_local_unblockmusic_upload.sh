#!/bin/sh
 
export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
upload_path=/tmp/upload
upload_file=/tmp/upload/UnblockNeteaseMusic

get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
mcenable=$(get merlinclash_enable)
muenable=$(get merlinclash_unblockmusic_enable)
local_binary_replace(){
	chmod +x $upload_file
	unblockmusic_upload_ver=$($upload_file -v 2>/dev/null |awk '/Version/{print $2}')
	unblockmusic_upload_ver2=$($upload_file -v 2>&1 |awk '/Version/{print $4}')
	if [ -n "$unblockmusic_upload_ver" ]; then
		un_flag=1
		echo_date "上传UnblockNeteaseMusic二进制版本为：$unblockmusic_upload_ver" >> $LOG_FILE
		replace_binary
	elif [ -n "$unblockmusic_upload_ver2" ]; then
		#echo_date "上传的二进制不合法！！！" >> $LOG_FILE		
		un_flag=2
		echo_date "上传UnblockNeteaseMusic二进制版本为：$unblockmusic_upload_ver2" >> $LOG_FILE
		replace_binary
	else
		echo_date "上传的二进制不合法！！！" >> $LOG_FILE
		echo BBABBBBC >> $LOG_FILE	
		exit 1
	fi
	
}

replace_binary(){
	echo_date "检查空间" >> $LOG_FILE
	SPACE_AVAL=$(df|grep jffs|head -n 1 | awk '{print $4}')
	SPACE_NEED=$(du -s /tmp/upload/UnblockNeteaseMusic | awk '{print $1}')
	if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
		echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 二进制需要"$SPACE_NEED" KB，空间满足，继续安装！ >> $LOG_FILE
		echo_date "开始载入UnblockNeteaseMusic!" >> $LOG_FILE
		if [ "$(pidof UnblockNeteaseMusic)" ];then
			echo_date "为了保证更新正确，先关闭UnblockNeteaseMusic... " >> $LOG_FILE
			killall UnblockNeteaseMusic >/dev/null 2>&1
			move_binary
			sleep 1
		else
			move_binary
		fi
	else
		echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 二进制需要"$SPACE_NEED" KB，空间不足！ >> $LOG_FILE
		echo_date 退出安装！ >> $LOG_FILE
		rm -rf /tmp/upload/UnblockNeteaseMusic
		exit 1
	fi
}


move_binary(){
	mv $upload_file /koolshare/bin/UnblockNeteaseMusic
	chmod +x /koolshare/bin/UnblockNeteaseMusic
	if [ "$un_flag" == "1" ]; then
		#unblockmusic_LOCAL_VER=$(/koolshare/bin/UnblockNeteaseMusic -v 2>/dev/null |awk '/Version/{print $2}')
		unblockmusic_LOCAL_VER=$unblockmusic_upload_ver
	fi
	if [ "$un_flag" == "2" ]; then
		#unblockmusic_LOCAL_VER=$(/koolshare/bin/UnblockNeteaseMusic -v 2>&1 |awk '/Version/{print $4}')
		unblockmusic_LOCAL_VER=$unblockmusic_upload_ver2
	fi
	[ -n "$unblockmusic_LOCAL_VER" ] && dbus set merlinclash_UnblockNeteaseMusic_version="$unblockmusic_LOCAL_VER"
	echo_date "UnblockNeteaseMusic上传完成... " >> $LOG_FILE
	if [ "$mcenable" == "1" ] && [ "$muenable" == "1" ]; then
		sh /koolshare/scripts/clash_unblockneteasemusic.sh restart
	fi
}

case $2 in
13)
	echo "本地上传UnblockNeteaseMusic二进制" > $LOG_FILE
	http_response "$1"
	local_binary_replace >> $LOG_FILE
	echo BBABBBBC >> $LOG_FILE	
	;;
esac