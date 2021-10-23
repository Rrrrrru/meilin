#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
dnsfile_path=/koolshare/merlinclash/yaml_dns
rh=$dnsfile_path/redirhost.yaml
fi=$dnsfile_path/fakeip.yaml
rm -rf /tmp/upload/dnsfile.log
nflag="0"
fflag="0"
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
dt=$(get merlinclash_dnsedit_tag)
mdec=$(get merlinclash_dns_edit_content1)
echo_date "测试脚本是否调用" >> /tmp/upload/dnsfile.log
echo_date "$dt" >> /tmp/upload/dnsfile.log
dns=$(decode_url_link $mdec)

if [ "$dt" == "redirhost" ]; then
	echo -e "$dns" > /koolshare/merlinclash/yaml_dns/redirhost.yaml
	echo_date "写入redirhost.yaml" >> /tmp/upload/dnsfile.log
	#删除空行
	sed -i '/^ *$/d' $rh
	rm -rf /tmp/upload/dns_redirhost.txt
	ln -sf $rh /tmp/upload/dns_redirhost.txt

fi

if [ "$dt" == "fakeip" ]; then
	echo -e "$dns" > $fi
	echo_date "fakeip.yaml" >> /tmp/upload/dnsfile.log
	#删除空行
	sed -i '/^ *$/d' $fi
	rm -rf /tmp/upload/dns_fakeip.txt
	ln -sf $fi /tmp/upload/dns_fakeip.txt
fi

http_response "$1"