#!/bin/sh
 
export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
upload_path=/tmp/upload/host
fp=/koolshare/merlinclash/yaml_basic/host
name=$(find $upload_path  -name "*.yaml" |sed 's#.*/##')
echo_date "host文件名是：$name" >> $LOG_FILE
host_tmp=/tmp/upload/host/$name

move_host(){
	#查找upload文件夹是否有刚刚上传的yaml文件，正常只有一份
	#name=$(find $uploadpath  -name "$yamlname.yaml" |sed 's#.*/##')
	echo_date "上传的文件名是$merlinclash_uploadhost" >> $LOG_FILE
	if [ -f "/tmp/upload/$merlinclash_uploadhost" ]; then
		echo_date "检查上传的host是否合法" >> $LOG_FILE
		para1=$(sed -n '/^hosts:/p' /tmp/upload/$merlinclash_uploadhost)
		if [ -n "$para1" ] ; then
			echo_date "上传的host合法" >> $LOG_FILE
			rm -rf /tmp/upload/host/
			mkdir -p /tmp/upload/host
			
			cp -rf /tmp/upload/$merlinclash_uploadhost /tmp/upload/host/$merlinclash_uploadhost
			mv -f /tmp/upload/host/$merlinclash_uploadhost /koolshare/merlinclash/yaml_basic/host/$merlinclash_uploadhost
			rm -rf /tmp/upload/host
			rm -rf /tmp/upload/*.yaml
			#生成新的txt文件
			rm -rf $fp/hosts.txt
			echo_date "创建host文件列表" >> $LOG_FILE
			echo 
			find $fp  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' >> $fp/hosts.txt
		
		else
			echo_date "上传的host不合法，请检查，即将退出" >> $LOG_FILE
			rm -rf /tmp/upload/$merlinclash_uploadhost
			echo BBABBBBC >> $LOG_FILE
			exit 1
		fi
		
	else
		echo_date "没找到上传的host文件" >> $LOG_FILE
		rm -rf /tmp/upload/$merlinclash_uploadhost
		echo BBABBBBC >> $LOG_FILE
		exit 1
	fi


}

case $2 in
22)
	echo "本地上传host文件" > $LOG_FILE
	http_response "$1"
	move_host >> $LOG_FILE
	echo BBABBBBC >> $LOG_FILE	
	;;
esac