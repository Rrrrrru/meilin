#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'

rm -rf /tmp/upload/clash_script.log
rm -rf /tmp/upload/clash_script.txt
b(){
	if [ -f "/koolshare/bin/base64_decode" ]; then #HND有这个
		base=base64_decode
		echo $base
	elif [ -f "/bin/base64" ]; then #HND是这个
		base=base64
		echo $base
	elif [ -f "/koolshare/bin/base64" ]; then #网件R7K是这个
		base=base64
		echo $base
	elif [ -f "/sbin/base64" ]; then
		base=base64
		echo $base
	else
		echo_date "固件缺少base64decode，无法正常订阅，直接退出" >> $LOG_FILE
		echo BBABBBBC >> $LOG_FILE
		exit 1
	fi
}
decode_url_link(){
	local link=$1
	local len=$(echo $link | wc -L)
	local mod4=$(($len%4))
	b64=$(b)
	echo_date "b64=$b64" >> LOG_FILE
	if [ "$mod4" -gt "0" ]; then
		local var="===="
		local newlink=${link}${var:$mod4}
		echo -n "$newlink" | sed 's/-/+/g; s/_/\//g' | $b64 -d 2>/dev/null
	else
		echo -n "$link" | sed 's/-/+/g; s/_/\//g' | $b64 -d 2>/dev/null
	fi
}
get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
msec=$(get merlinclash_script_edit_content1)
echo_date "测试脚本是否调用" >> /tmp/upload/clash_script.log
script=$(decode_url_link $msec)

echo -e "$script" > /koolshare/merlinclash/yaml_basic/script.yaml
ln -sf /koolshare/merlinclash/yaml_basic/script.yaml /tmp/upload/clash_script.txt

echo_date "生成script.yaml" >> /tmp/upload/clash_script.log

http_response "$1"