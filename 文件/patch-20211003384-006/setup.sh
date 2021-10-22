#! /bin/sh

source /koolshare/scripts/base.sh
eval $(dbus export merlinclash)
alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'
MODEL=$(nvram get productid)
LOG_FILE=/tmp/upload/merlinclash_log.txt
yamlname=$merlinclash_yamlsel
LINUX_VER=$(uname -r|awk -F"." '{print $1$2}')
#配置文件路径
#yamlpath=/koolshare/merlinclash/yaml_use/$yamlname.yaml
lan_ipaddr=$(nvram get lan_ipaddr)
#dnslistenport=$(cat $yamlpath | awk -F: '/listen/{print $3}' | xargs echo -n)
#name:设置为补丁包名字。每次补丁都需要重命名与补丁包一致
name=$1
dbus set merlinclash_linuxver="$LINUX_VER"
	echo_date 开始复制文件！ >> $LOG_FILE
	echo_date 复制补丁文件！此步时间可能较长！
	#dbus set merlinclash_flag="384"
	#卸载模块
	#rmmod ip_set_hash_mac.ko >/dev/null 2>&1 &
	#dbus set merlinclash_bypassmode="1"
	#dbus set merlinclash_tproxymode="closed"
	#dbus set merlinclash_unblock_check="1"
	#dbus set merlinclash_unblock_check="1"
	#dbus set merlinclash_mark_MD51=""
	

	dir=/tmp/clashpatch/$name/clash
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		echo ""
		cp -rf /tmp/clashpatch/$name/clash/clashconfig.sh /koolshare/merlinclash/
		echo_date "重建host文件列表"
		find /koolshare/merlinclash/yaml_basic/host  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_basic/host/hosts.txt
		#0813-001才有
		#cp -rf /tmp/clashpatch/$name/clash/clash /koolshare/bin/
		#merlinclash_clash_version_tmp=$(/koolshare/bin/clash -v 2>/dev/null | head -n 1 | cut -d " " -f2)
		#if [ -n "$merlinclash_clash_version_tmp" ]; then
		#	merlinclash_clash_version="$merlinclash_clash_version_tmp"		
		#else
		#	merlinclash_clash_version="null"
		#fi
		#dbus set merlinclash_clash_version="$merlinclash_clash_version"
		
		sleep 1s
		#设置清除自定义DNS默认值为1
		
		#dbus set merlinclash_links=" "
		#dbus set merlinclash_links2=" "
		#dbus set merlinclash_links3=" "
		#清除旧格式53端口ipt
		#dns2_indexs=$(iptables -nvL PREROUTING -t nat | sed 1,2d | sed -n "/"${lan_ipaddr}":"${dnslistenport}"/=" | sort -r)
		#for dns2_index in $dns2_indexs; do
		#	iptables -t nat -D PREROUTING $dns2_index >/dev/null 2>&1
		#done
	fi
	
	#------KOOLPROXY内容-----------
	dir=/tmp/clashpatch/$name/koolproxy
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/koolproxy/* /koolshare/merlinclash/koolproxy/
	fi
	#------KOOLPROXY内容-----------

	#------网易云内容-----------
	dir=/tmp/clashpatch/$name/UnblockMusic
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/UnblockMusic/* /koolshare/bin/UnblockMusic/
	fi
	#------网易云内容-----------
	
	
	
	cp -rf /tmp/clashpatch/$name/version /koolshare/merlinclash/

	dir=/tmp/clashpatch/$name/yaml_basic
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then

		cp -rf /tmp/clashpatch/$name/yaml_basic/* /koolshare/merlinclash/yaml_basic/
		#merlinclash_proxygroup_version="2020081701"
		#dbus set merlinclash_proxygroup_version=$merlinclash_proxygroup_version
	fi

	dir=/tmp/clashpatch/$name/yaml_dns
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/yaml_dns/* /koolshare/merlinclash/yaml_dns/
	fi

	dir=/tmp/clashpatch/$name/dashboard
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		#rm -rf /koolshare/merlinclash/dashboard/yacd/*
		cp -rf /tmp/clashpatch/$name/dashboard/* /koolshare/merlinclash/dashboard/
	fi
	

	dir=/tmp/clashpatch/$name/scripts
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/scripts/* /koolshare/scripts/
		chmod 755 /koolshare/scripts/clash*
	fi
	
	dir=/tmp/clashpatch/$name/webs
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/webs/* /koolshare/webs/
	fi
	
	dir=/tmp/clashpatch/$name/res
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]; then
		cp -rf /tmp/clashpatch/$name/res/* /koolshare/res/
	fi
	
	
	if [ "$ROG" == "1" ];then
		cp -rf /tmp/clashpatch/$name/rog/res/merlinclash.css /koolshare/res/
    fi