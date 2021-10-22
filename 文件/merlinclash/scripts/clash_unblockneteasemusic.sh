#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt

ROUTE_IP=$(nvram get lan_ipaddr)
ipt_n="iptables -t nat"
serverCrt="/koolshare/bin/UnblockMusic/server.crt"
serverKey="/koolshare/bin/UnblockMusic/server.key"
ipset_music=$(ipset list music)

get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
get_list(){
	b=$(echo $(dbus list $1 | cut -d "=" -f $2 | cut -d "_" -f $3 | sort -n))
	b=$(echo $(dbus list $1 | cut -d "=" -f $2 | cut -d "_" -f $3 | sort -n))
	echo $b
}
mue=$(get merlinclash_unblockmusic_enable)
muend=$(get merlinclash_unblockmusic_endpoint)
muversion=$(get merlinclash_UnblockNeteaseMusic_version)
mupn=$(get merlinclash_unblockmusic_platforms_numbers)
mumuscitype=$(get merlinclash_unblockmusic_musicapptype)
mubest=$(get merlinclash_unblockmusic_bestquality)
mulog=$(get merlinclash_unblockmusic_log)
factor(){
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
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
			echo "UNM_service"
		;;
	esac
}

get_mode_name() {
	case "$1" in
		0)
			echo "不解锁"
		;;
		1)
			echo "解锁"
		;;
	esac
}

mcuad=$(get merlinclash_unblockmusic_acl_default)
lan_acess_control(){
	# lan access control
	[ -z "$mcuad" ] && mcuad=1
	acl_nu=$(get_list merlinclash_unblockmusic_acl_mode 1 5)
	if [ -n "$acl_nu" ]; then
		for min in $acl_nu
		do
			ipaddr=`dbus get merlinclash_unblockmusic_acl_ip_$min`
			mac=`dbus get merlinclash_unblockmusic_acl_mac_$min`
			proxy_name=`dbus get merlinclash_unblockmusic_acl_name_$min`
			proxy_mode=`dbus get merlinclash_unblockmusic_acl_mode_$min`
		
		#	iptables -t nat -A cloud_music $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -p tcp $(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			iptables -t nat -A cloud_music $(factor $ipaddr "-s") -p tcp $(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
		done
		echo_date 加载ACL规则：其余主机模式为：$(get_mode_name $mcuad) >> $LOG_FILE
	else
		echo_date 加载ACL规则：所有模式为：$(get_mode_name $mcuad) >> $LOG_FILE
	fi
}

add_rule()
{
	
		ipset -! -N music hash:ip
		muu=$(get merlinclash_unblockmusic_unblockplan)
		case $muu in
		old)
			ipset add music 59.111.181.60 
			ipset add music 59.111.181.38 
			ipset add music 59.111.181.35 
			ipset add music 59.111.160.195
			ipset add music 223.252.199.66
			ipset add music 59.111.160.197
			ipset add music 223.252.199.67
			ipset add music 115.236.121.1
			ipset add music 115.236.121.3
			ipset add music 115.236.118.33
			ipset add music 39.105.63.80
			ipset add music 118.24.63.156
			ipset add music 193.112.159.225
			ipset add music 47.100.127.239
			#20200712++++
			ipset add music 112.13.122.1
			ipset add music 112.13.119.17
			ipset add music 103.126.92.133
			ipset add music 103.126.92.132
			ipset add music 101.71.154.241
			ipset add music 59.111.238.29
			ipset add music 59.111.179.214
			ipset add music 59.111.21.14
			ipset add music 45.254.48.1
			ipset add music 42.186.120.199
			#20200712++++
			ipset add music 119.147.70.226 
			ipset add music 121.9.246.105 
			ipset add music 222.243.46.13 
			ipset add music 218.13.191.173 
			ipset add music 59.111.160.195 
			ipset add music 222.243.46.12
			ipset add music 223.252.199.67 
			ipset add music 222.243.46.14 
			ipset add music 222.243.46.7 
			ipset add music 222.243.46.9 
			ipset add music 14.152.86.35 
			;;
		new)
			curl -4s "https://httpdns.n.netease.com/httpdns/v2/d?session_id=1609320571828_26796&domain=clientlog.music.163.com,interface.music.163.com,m7.music.126.net,m701.music.126.net,m8.music.126.net,m801.music.126.net,m9.music.126.net,music.163.com,p1.music.126.net,p2.music.126.net,p3.music.126.net,p4.music.126.net,p5.music.126.net,p6.music.126.net,vodkgeyttp8.vod.126.net,vodkgeyttp9.vod.126.net" | grep -Eo '[0-9]+?\.[0-9]+?\.[0-9]+?\.[0-9]+?' | sort | uniq | awk '{print "ipset -! add music "$1}' >/koolshare/res/163.sh
			chmod 755 /koolshare/res/163.sh
			sh /koolshare/res/163.sh >/dev/null 2>&1
			rm -rf /koolshare/res/163.sh >/dev/null 2>&1
			;;
		*)
			ipset add music 59.111.181.60 
			ipset add music 59.111.181.38 
			ipset add music 59.111.181.35 
			ipset add music 59.111.160.195
			ipset add music 223.252.199.66
			ipset add music 59.111.160.197
			ipset add music 223.252.199.67
			ipset add music 115.236.121.1
			ipset add music 115.236.121.3
			ipset add music 115.236.118.33
			ipset add music 39.105.63.80
			ipset add music 118.24.63.156
			ipset add music 193.112.159.225
			ipset add music 47.100.127.239
			#20200712++++
			ipset add music 112.13.122.1
			ipset add music 112.13.119.17
			ipset add music 103.126.92.133
			ipset add music 103.126.92.132
			ipset add music 101.71.154.241
			ipset add music 59.111.238.29
			ipset add music 59.111.179.214
			ipset add music 59.111.21.14
			ipset add music 45.254.48.1
			ipset add music 42.186.120.199
			#20200712++++
			ipset add music 119.147.70.226 
			ipset add music 121.9.246.105 
			ipset add music 222.243.46.13 
			ipset add music 218.13.191.173 
			ipset add music 59.111.160.195 
			ipset add music 222.243.46.12
			ipset add music 223.252.199.67 
			ipset add music 222.243.46.14 
			ipset add music 222.243.46.7 
			ipset add music 222.243.46.9 
			ipset add music 14.152.86.35 
			;;
		esac
		list=$(ipset list music | grep -Eo "Number of entries:.*" | awk -F "[: ]" '{print $5}')
		if [ "$list" == "0" ]; then
			echo_date "获取163相关ip失败，不启动云村解锁" >> $LOG_FILE
			stop_unblockmusic
		else
			muv=$(get merlinclash_unblockmusic_vip)
			if [ "$muv" == "0" ]; then
				ipset del music 14.152.86.35 >/dev/null 2>&1 &
			fi
		fi
	$ipt_n -N cloud_music
	#$ipt_n -A cloud_music -d 0.0.0.0/8 -j RETURN
	#$ipt_n -A cloud_music -d 10.0.0.0/8 -j RETURN
	#$ipt_n -A cloud_music -d 127.0.0.0/8 -j RETURN
	#$ipt_n -A cloud_music -d 169.254.0.0/16 -j RETURN
	#$ipt_n -A cloud_music -d 172.16.0.0/12 -j RETURN
	#$ipt_n -A cloud_music -d 192.168.0.0/16 -j RETURN
	#$ipt_n -A cloud_music -d 224.0.0.0/4 -j RETURN
	#$ipt_n -A cloud_music -d 240.0.0.0/4 -j RETURN
	#$ipt_n -A cloud_music -p tcp --dport 80 -j REDIRECT --to-ports 5200
	#$ipt_n -A cloud_music -p tcp --dport 443 -j REDIRECT --to-ports 5300
	$ipt_n -A cloud_music -m set --match-set direct_list dst -j RETURN
	#  生成对应CHAIN
	$ipt_n -N UNM_service
	$ipt_n -A UNM_service -p tcp --dport 80 -j REDIRECT --to-ports 5200
	$ipt_n -A UNM_service -p tcp --dport 443 -j REDIRECT --to-ports 5300

	KP_NU=$(iptables -nvL PREROUTING -t nat | sed 1,2d | sed -n '/KOOLPROXY/=' | head -n1)
	[ "$KP_NU" == "" ] && KP_NU=0
	INSET_NU=$(expr "$KP_NU" + 1)
	$ipt_n -I PREROUTING "$INSET_NU" -p tcp -m set --match-set music dst -j cloud_music
	#iptables -I OUTPUT -d 223.252.199.10 -j DROP
	# 局域网控制
	lan_acess_control
	# 剩余流量转发到缺省规则定义的链中
	iptables -t nat -A cloud_music -p tcp -j $(get_action_chain $mcuad)
}

del_rule(){
	echo_date 移除网易云音乐解锁nat规则... >> $LOG_FILE
	$ipt_n -D PREROUTING -p tcp -m set --match-set music dst -j cloud_music >/dev/null 2>&1 
	#iptables -D OUTPUT -d 223.252.199.10 -j DROP >/dev/null 2>&1 
	$ipt_n -F cloud_music  >/dev/null 2>&1 
	$ipt_n -X cloud_music  >/dev/null 2>&1 	
	$ipt_n -F UNM_service  >/dev/null 2>&1 
	$ipt_n -X UNM_service  >/dev/null 2>&1 	
	ipset -! flush music >/dev/null 2>&1
	rm -f /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	service restart_dnsmasq >/dev/null 2>&1
}

set_firewall(){
	echo_date 加载网易云音乐解锁nat规则... >> $LOG_FILE
	if [ -n "$ipset_music" ]; then
		echo_date "已存在ipset规则，重建" >> $LOG_FILE
		ipset -! flush music >/dev/null 2>&1
	fi
	rm -f /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/interface.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/interface3.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/apm.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/apm3.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/clientlog.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/clientlog3.music.163.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/.music.126.net/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/.dun.163yun.com/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/.acstatic-dun.126.net/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#echo "ipset=/.vod.126.net/music" >> /jffs/configs/dnsmasq.d/dnsmasq-music.conf
	#service restart_dnsmasq >/dev/null 2>&1
	add_rule
}

remove_unblock_restart_job(){
	if [ -n "$(cru l|grep unblock_restart)" ]; then
		echo_date "删除网易云音乐解锁自动重启定时任务..." >> $LOG_FILE
		sed -i '/unblock_restart/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
	fi
}

start_unblock_restart_job_day(){
	remove_unblock_restart_job
	echo_date "创建网易云音乐解锁自动重启定时任务..." >> $LOG_FILE
	cru a unblock_restart ${merlinclash_select_minute} ${merlinclash_select_hour}" * * * /bin/sh /koolshare/scripts/clash_unblockneteasemusic.sh restart"
}
start_unblock_restart_job_week(){
	remove_unblock_restart_job
	echo_date "创建网易云音乐解锁自动重启定时任务..." >> $LOG_FILE
	cru a unblock_restart ${merlinclash_select_minute} ${merlinclash_select_hour}" * * "${merlinclash_select_week}" /bin/sh /koolshare/scripts/clash_unblockneteasemusic.sh restart"
}
start_unblock_restart_job_month(){
	remove_unblock_restart_job
	echo_date "创建网易云音乐解锁自动重启定时任务..." >> $LOG_FILE
	cru a unblock_restart ${merlinclash_select_minute} ${merlinclash_select_hour} ${merlinclash_select_day}" * * /bin/sh /koolshare/scripts/clash_unblockneteasemusic.sh restart"

}

start_unblock_restart_job(){
	msj=$(get merlinclash_select_job)
	case $msj in
	1)
		remove_unblock_restart_job
		;;
	2)
		start_unblock_restart_job_day
		;;
	3)
		start_unblock_restart_job_week
		;;
	4)
		start_unblock_restart_job_month
		;;
	esac
}

start_unblockmusic(){
	echo_date "开启网易云音乐解锁功能" >> $LOG_FILE
	rm -rf /tmp/upload/UnblockMusic.log

	stop_unblockmusic
	remove_unblock_restart_job

	if [ $mue -eq 0 ]; then
		echo_date "解锁开关未开启，退出" >> $LOG_FILE
		exit 0
	fi
	endponintset="";

	if [ -n "$muend" ]; then
		endponintset="-e"
	fi
	ver="0.2.5"
	echo_date "当前二进制版本为$muversion" >> $LOG_FILE
	COMP=$(versioncmp $muversion $ver)
	if [ "$COMP" == "-1" ] || [ "$COMP" == "0" ]  ; then

		echo_date "当前版本可开启显示搜索结果数：$mupn" >> $LOG_FILE

		if [ "$mumuscitype" == "default" ]; then
			if [ "$mubest" == "1" ]; then
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -sl "${mupn}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -sl "${mupn}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b >/dev/null 2>&1 &
				fi
			else
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -sl "${mupn}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -sl "${mupn}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" >/dev/null 2>&1 &
				fi
			fi
		
		else
			if [ "$mubest" == "1" ]; then
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -sl "${merlinclash_unblockmusic_platforms_numbers}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -sl "${merlinclash_unblockmusic_platforms_numbers}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b >/dev/null 2>&1 &
				fi					
			else
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -sl "${merlinclash_unblockmusic_platforms_numbers}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -sl "${merlinclash_unblockmusic_platforms_numbers}" -c "${serverCrt}" -k "${serverKey}" "${endponintset}" >/dev/null 2>&1 &
				fi
			fi
		fi
	else
		echo_date "当前版本不可开启显示搜索结果数" >> $LOG_FILE
		if [ "$mumuscitype" == "default" ]; then
			if [ "$mubest" == "1" ]; then
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b >/dev/null 2>&1 &
				fi
			else
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" >/dev/null 2>&1 &
				fi
			fi
		
		else
			if [ "$mubest" == "1" ]; then
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -b >/dev/null 2>&1 &
				fi	
			else
				if [ "$mulog" == "1" ]; then
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" -l /tmp/upload/UnblockMusic.log 2>&1 &
				else
					/koolshare/bin/UnblockNeteaseMusic -p 5200 -sp 5300 -o "$mumuscitype" -m 0 -c "${serverCrt}" -k "${serverKey}" "${endponintset}" >/dev/null 2>&1 &
				fi
			fi
		
		fi
		
	fi
	
	echo_date "设置相关iptable规则" >> $LOG_FILE
	set_firewall
	ubm_process=$(pidof UnblockNeteaseMusic);
	if [ -n "$ubm_process" ]; then
		echo_date "网易云音乐解锁启动完成，pid：$ubm_process" >> $LOG_FILE
		start_unblock_restart_job
	else
		echo_date "网易云音乐解锁启动失败" >> $LOG_FILE
		rm -rf /tmp/upload/unblockmusic.log
		
	fi
}

stop_unblockmusic(){
	kill -9 $(busybox ps -w | grep UnblockNeteaseMusic | grep -v grep | awk '{print $1}') >/dev/null 2>&1 &
	rm -f /tmp/upload/unblockmusic.log
	del_rule
	remove_unblock_restart_job
}

case $1 in
start)
	if [ "$mue" == "1" ]; then
		echo_date "开启网易云音乐解锁" >> $LOG_FILE
		start_unblockmusic
	fi
	;;
restart)
	if [ "$mue" == "1" ]; then
		echo_date "开启网易云音乐解锁" >> $LOG_FILE
		start_unblockmusic
	fi
	;;
stop)
	echo_date "关闭网易云音乐解锁" >> $LOG_FILE
	stop_unblockmusic
	;;
*)
	if [ "$mue" == "1" ]; then
		start_unblockmusic
	else
		stop_unblockmusic
	fi
	;;
esac

