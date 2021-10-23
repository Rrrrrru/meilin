#! /bin/sh

# shadowsocks script for HND router with kernel 4.1.27 merlin firmware
# by sadog (sadoneli@gmail.com) from koolshare.cn

alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'
export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval `dbus export merlinclash`
SOFT_DIR=/koolshare
KP_DIR=$SOFT_DIR/merlinclash/koolproxy
lan_ipaddr=$(nvram get lan_ipaddr)
LOCK_FILE=/var/lock/koolproxy.lock
LOG_FILE=/tmp/upload/merlinclash_log.txt
#=======================================

set_lock(){
	exec 1000>"$LOCK_FILE"
	flock -x 1000
}

unset_lock(){
	flock -u 1000
	rm -rf "$LOCK_FILE"
}
get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
get_lan_cidr(){
	netmask=`nvram get lan_netmask`
	local x=${netmask##*255.}
	set -- 0^^^128^192^224^240^248^252^254^ $(( (${#netmask} - ${#x})*2 )) ${x%%.*}
	x=${1%%$3*}
	suffix=$(( $2 + (${#x}/4) ))
	#prefix=`nvram get lan_ipaddr | cut -d "." -f1,2,3`
	echo $lan_ipaddr/$suffix
}

mks=$(get merlinclash_koolproxy_sourcelist)
mkm=$(get merlinclash_koolproxy_mode)
mkad=$(get merlinclash_koolproxy_acl_default)
write_sourcelist(){
	if [ -n "$mks" ];then
		echo $mks|sed 's/>/\n/g' > $KP_DIR/data/source.list
	else
		cat > $KP_DIR/data/source.list <<-EOF
			1|koolproxy.txt||
			1|daily.txt||
			1|kp.dat||
			1|user.txt||
			
		EOF
	fi
	mkcr=$(get merlinclash_koolproxy_custom_rule)
	if [ -n "$mkcr" ];then
		echo $mkcr| base64_decode |sed 's/\\n/\n/g' > $KP_DIR/data/rules/user.txt
		dbus remove merlinclash_koolproxy_custom_rule
	fi
}

start_koolproxy(){
	write_sourcelist
	
	echo_date 开启KP主进程！>> $LOG_FILE
	[ ! -L "$KSROOT/bin/koolproxy" ] && ln -sf $KSROOT/merlinclash/koolproxy/koolproxy $KSROOT/bin/koolproxy
	cd $KP_DIR && koolproxy --mark -d
	[ "$?" != "0" ] && echo_date "koolproxy启动失败" >> $LOG_FILE && dbus set merlinclash_koolproxy_enable=0 && exit 1
}

stop_koolproxy(){
	if [ -n "`pidof koolproxy`" ];then
		echo_date 关闭KP主进程... >> $LOG_FILE
		kill -9 `pidof koolproxy` >/dev/null 2>&1
		killall koolproxy >/dev/null 2>&1
	fi
	flush_nat
}

add_ipset_conf(){

	if [ "$mkm" == "2" ];then
		echo_date 添加黑名单软连接... >> $LOG_FILE
		rm -rf /jffs/configs/dnsmasq.d/koolproxy_ipset.conf
		ln -sf /koolshare/merlinclash/koolproxy/data/koolproxy_ipset.conf /jffs/configs/dnsmasq.d/koolproxy_ipset.conf
		dnsmasq_restart=1
	fi
}

remove_ipset_conf(){
	if [ -L "/jffs/configs/dnsmasq.d/koolproxy_ipset.conf" ];then
		echo_date 移除黑名单软连接... >> $LOG_FILE
		rm -rf /jffs/configs/dnsmasq.d/koolproxy_ipset.conf
		dnsmasq_restart=1
	fi
}

restart_dnsmasq(){
	if [ "$dnsmasq_restart" == "1" ];then
		echo_date 重启dnsmasq进程... >> $LOG_FILE
		service restart_dnsmasq > /dev/null 2>&1
	fi
}

write_reboot_job(){
	# start setvice
	mkr=$(get merlinclash_koolproxy_reboot)
	mkrh=$(get merlinclash_koolproxy_reboot_hour)
	mkrm=$(get merlinclash_koolproxy_reboot_min)
	mkrih=$(get merlinclash_koolproxy_reboot_inter_hour)
	mkrim=$(get merlinclash_koolproxy_reboot_inter_min)
	if [ "1" == "$mkr" ]; then
		echo_date 开启插件定时重启，每天"$mkrh"时"$mkrm"分，自动重启插件... >> $LOG_FILE
		cru a c_koolproxy_reboot "$mkrm $mkrh * * * /bin/sh /koolshare/scripts/clash_koolproxyconfig.sh restart"
	elif [ "2" == "$mkr" ]; then
		echo_date 开启插件间隔重启，每隔"$mkrih"时"$mkrim"分，自动重启插件... >> $LOG_FILE
		cru a c_koolproxy_reboot "*/$mkrim */$mkrih * * * /bin/sh /koolshare/scripts/clash_koolproxyconfig.sh restart"
	fi
}

remove_reboot_job(){
	jobexist=`cru l|grep c_koolproxy_reboot`
	# kill crontab job
	if [ -n "$jobexist" ];then
		echo_date 关闭插件定时重启... >> $LOG_FILE
		sed -i '/c_koolproxy_reboot/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
	fi
}

creat_ipset(){
	echo_date 创建ipset名单 >> $LOG_FILE
	ipset -! creat white_kp_list nethash
	ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
	for ip in $ip_lan
	do
		ipset -A white_kp_list $ip >/dev/null 2>&1
	done
	
	ports=`cat /koolshare/merlinclash/koolproxy/data/rules/koolproxy.txt | grep -Eo "(.\w+\:[1-9][0-9]{1,4})/" | grep -Eo "([0-9]{1,5})" | sort -un`
	for port in $ports 80
	do
		ipset -A kp_port_http $port >/dev/null 2>&1
		ipset -A kp_port_https $port >/dev/null 2>&1
	done

	ipset -A kp_port_https 443 >/dev/null 2>&1
	ipset -A black_koolproxy 110.110.110.110 >/dev/null 2>&1
	
}

get_mode_name() {
	case "$1" in
		0)
			echo "不过滤"
		;;
		1)
			echo "http模式"
		;;
		2)
			echo "http + https"
		;;
	esac
}

get_jump_mode(){
	case "$1" in
		0)
			echo "-j"
		;;
		*)
			echo "-g"
		;;
	esac
}

get_action_chain() {
	case "$1" in
		0)
			echo "RETURN"
		;;
		1)
			echo "KP_HTTP"
		;;
		2)
			echo "KP_HTTPS"
		;;
	esac
}

factor(){
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

flush_nat(){
	#iptables -t nat -D KP_HTTPS -p tcp -m set ! --match-set  china_ip_route dst -j RETURN
	if [ -n "`iptables -t nat -S|grep KOOLPROXY`" ];then
		echo_date 移除nat规则... >> $LOG_FILE
		cd /tmp
		iptables -t nat -S | grep -E "KOOLPROXY|KP_HTTP|KP_HTTPS" | sed 's/-A/iptables -t nat -D/g'|sed 1,3d > clean.sh && chmod 777 clean.sh && ./clean.sh > /dev/null 2>&1 && rm clean.sh
		iptables -t nat -X KOOLPROXY > /dev/null 2>&1
		iptables -t nat -X KP_HTTP > /dev/null 2>&1
		iptables -t nat -X KP_HTTPS > /dev/null 2>&1
	fi
}

lan_acess_control(){
	# lan access control

	[ -z "$mkad" ] && mkad=1
	acl_nu=`dbus list merlinclash_koolproxy_acl_mode_ | cut -d "=" -f 1 | cut -d "_" -f 5 | sort -n`
	if [ -n "$acl_nu" ]; then
		for min in $acl_nu
		do
			ipaddr=`dbus get merlinclash_koolproxy_acl_ip_$min`
			mac=`dbus get merlinclash_koolproxy_acl_mac_$min`
			proxy_name=`dbus get merlinclash_koolproxy_acl_name_$min`
			proxy_mode=`dbus get merlinclash_koolproxy_acl_mode_$min`
			mkamt=$(get merlinclash_koolproxy_acl_method)
			[ "$mkamt" == "1" ] && echo_date 加载ACL规则：【$ipaddr】【$mac】模式为：$(get_mode_name $proxy_mode) >> $LOG_FILE
			[ "$mkamt" == "2" ] && mac="" && echo_date 加载ACL规则：【$ipaddr】模式为：$(get_mode_name $proxy_mode) >> $LOG_FILE
			[ "$mkamt" == "3" ] && ipaddr="" && echo_date 加载ACL规则：【$mac】模式为：$(get_mode_name $proxy_mode) >> $LOG_FILE
			#echo iptables -t nat -A KOOLPROXY $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -p tcp $(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			iptables -t nat -A KOOLPROXY $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -p tcp $(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
		done
		echo_date 加载ACL规则：其余主机模式为：$(get_mode_name $mkad) >> $LOG_FILE
	else
		echo_date 加载ACL规则：所有模式为：$(get_mode_name $mkad) >> $LOG_FILE
	fi
}

load_nat(){
	nat_ready=$(iptables -t nat -L PREROUTING -v -n --line-numbers|grep -v PREROUTING|grep -v destination)
	i=120
	# laod nat rules
	until [ -n "$nat_ready" ]
	do
	    i=$(($i-1))
	    if [ "$i" -lt 1 ];then
	        echo_date "Could not load nat rules!" >> $LOG_FILE
	        sh /koolshare/scipts/clash_koolproxyconfig.sh stop
	        exit
	    fi
	    sleep 1
		nat_ready=$(iptables -t nat -L PREROUTING -v -n --line-numbers|grep -v PREROUTING|grep -v destination)
	done
	
	echo_date 加载nat规则！ >> $LOG_FILE
	#----------------------BASIC RULES---------------------
	echo_date 写入iptables规则到nat表中... >> $LOG_FILE
	# 创建KOOLPROXY nat rule
	iptables -t nat -N KOOLPROXY
	# 局域网地址不走KP
	iptables -t nat -A KOOLPROXY -m set --match-set direct_list dst -j RETURN
	#  生成对应CHAIN
	iptables -t nat -N KP_HTTP
	#iptables -t nat -A KP_HTTP -p tcp -m multiport --dport 80,82,8080 -j REDIRECT --to-ports 3000
	iptables -t nat -A KP_HTTP -p tcp -m set --match-set music dst -j RETURN
	iptables -t nat -A KP_HTTP -p tcp -m set --match-set kp_port_http dst -j REDIRECT --to-ports 3000
	iptables -t nat -N KP_HTTPS
	#iptables -t nat -A KP_HTTPS -p tcp -m multiport --dport 80,82,443,8080 -j REDIRECT --to-ports 3000
	#TUN_NU=$(iptables -nvL PREROUTING -t mangle | sed 1,2d | sed -n '/tun/=' | head -n1)
	mpkp=$(get merlinclash_passkpswitch)
	if [ "$mpkp" == "1" ]; then
		echo_date "国外IP绕行开启，设置国外IP绕开koolproxy" >> $LOG_FILE
		iptables -t nat -I KP_HTTP 1 -p tcp -m set ! --match-set  china_ip_route dst -j RETURN
		iptables -t nat -I KP_HTTPS 1 -p tcp -m set ! --match-set  china_ip_route dst -j RETURN	
	fi
	
	iptables -t nat -A KP_HTTPS -p tcp -m set --match-set music dst -j RETURN
	iptables -t nat -A KP_HTTPS -p tcp -m set --match-set kp_port_https dst -j REDIRECT --to-ports 3000
	# 局域网控制
	lan_acess_control
	# 剩余流量转发到缺省规则定义的链中
	iptables -t nat -A KOOLPROXY -p tcp -j $(get_action_chain $mkad)
	# 重定所有流量到 KOOLPROXY
	# 全局模式和视频模式
	[ "$mkm" == "1" ] || [ "$mkm" == "3" ] && iptables -t nat -I PREROUTING 1 -p tcp -j KOOLPROXY
	# ipset 黑名单模式
	[ "$mkm" == "2" ] && iptables -t nat -I PREROUTING 1 -p tcp -m set --match-set black_koolproxy dst -j KOOLPROXY
}

dns_takeover(){
	lan_ipaddr=`nvram get lan_ipaddr`
	#chromecast=`iptables -t nat -L PREROUTING -v -n|grep "dpt:53"`
	chromecast_nu=`iptables -t nat -L PREROUTING -v -n --line-numbers|grep "dpt:53"|awk '{print $1}'`
	if [ "$mkm" == "2" ]; then
		if [ -z "$chromecast_nu" ]; then
			echo_date 黑名单模式开启DNS劫持 >> $LOG_FILE
			iptables -t nat -A PREROUTING -p udp -s $(get_lan_cidr) --dport 53 -j DNAT --to $lan_ipaddr:23453 >/dev/null 2>&1
		fi
	fi
}

detect_cert(){
	if [ ! -f $KP_DIR/data/private/ca.key.pem ]; then
		echo_date 检测到首次运行，开始生成KP证书，用于https过滤！ >> $LOG_FILE
		cd $KP_DIR/data && sh gen_ca.sh
		echo_date 证书生成完毕！！！ >> $LOG_FILE
	fi
}

case $1 in
restart)
	#web提交触发，需要先关后开
	# now stop
	rm -rf /tmp/upload/user.txt && ln -sf $KSROOT/merlinclash/koolproxy/data/rules/user.txt /tmp/upload/user.txt
	remove_reboot_job
	#flush_nat
	stop_koolproxy
	remove_ipset_conf && restart_dnsmasq
	# now start
	echo_date ============================ KP启用 =========================== >> $LOG_FILE
	detect_cert
	start_koolproxy
	add_ipset_conf && restart_dnsmasq
	#creat_ipset
	load_nat
	dns_takeover
	write_reboot_job
	detect_start_up
	echo_date KP启用成功，请等待日志窗口自动关闭，页面会自动刷新... >> $LOG_FILE
	echo_date ============================================================= >> $LOG_FILE
	;;
stop)
	#web提交触发，需要先关后开
	echo_date ============================ 关闭KP =========================== >> $LOG_FILE
	remove_reboot_job
	add_ipset_conf && restart_dnsmasq
	#flush_nat
	stop_koolproxy
	remove_ipset_conf && restart_dnsmasq
	echo_date KP插件已关闭 >> $LOG_FILE
	echo_date ============================================================= >> $LOG_FILE
	;;
esac