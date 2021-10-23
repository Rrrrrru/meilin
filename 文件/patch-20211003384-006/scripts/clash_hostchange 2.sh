#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
hostsel=$(dbus get merlinclash_hostsel)
rm -rf /tmp/upload/clash_host.log
rm -rf /tmp/upload/${hostsel}.txt

count=$(dbus get merlinclash_host_content1_count)
file=$(dbus get merlinclash_hostsel)

urldecode(){
  echo -e "$(sed 's/+/ /g;s/%\(..\)/\\x\1/g;')"
}

decode_url_link(){
	local link=$1
	local len=$(echo $link | wc -L)
	local mod4=$(($len%4))
	if [ "$mod4" -gt "0" ]; then
		local var="===="
		local newlink=${link}${var:$mod4}
		echo -n "$newlink" | sed 's/-/+/g; s/_/\//g' | base64 -d 2>/dev/null
	else
		echo -n "$link" | sed 's/-/+/g; s/_/\//g' | base64 -d 2>/dev/null
	fi
}

sleep 1
if [ -n "$count" ];then
		i=0
		while [ "$i" -lt "$count" ]
		do
			txt=$(dbus get merlinclash_host_content1_$i)
			#开始拼接文件值，然后进行base64解码，写回文件
			content=${content}${txt}
			let i=i+1
		done
		echo $content| base64_decode > /tmp/hostyaml.txt
		if [ -f /tmp/hostyaml.txt ]; then
			echo_date "中间文件已经创建好了" >> $LOG_FILE
			echo_date "生成新文件" >> $LOG_FILE
			cat /tmp/hostyaml.txt | urldecode > /koolshare/merlinclash/yaml_basic/host/${file}.yaml 2>&1
			rm -rf /tmp/hostyaml.txt
		fi
		#dbus remove jdqd_jd_script_content_custom
		customs=`dbus list merlinclash_host_content1_ | cut -d "=" -f 1`
		for custom in $customs
		do
			dbus remove $custom
		done
	fi


ln -sf /koolshare/merlinclash/yaml_basic/host/${file}.yaml /tmp/upload/${file}.txt


http_response "$1"