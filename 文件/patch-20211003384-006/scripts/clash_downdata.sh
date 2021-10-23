#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
name=$(echo "/tmp/clash_backup.tar.gz"|sed 's/.tar.gz//g')
#echo_date "download" >> $LOG_FILE
#echo_date "定位文件" >> $LOG_FILE
mcflag=$(dbus get merlinclash_flag)

backup_conf(){
	rm -rf /tmp/clash_backup
	rm -rf /tmp/clash_backup.tar.gz
	rm -rf /tmp/upload/clash_backup.tar.gz
	echo_date "建立备份数据文件夹" > $LOG_FILE
	mkdir -p /tmp/clash_backup
	echo_date "备份merlinclash skidpd相关数据" >> $LOG_FILE
	dbus list merlinclash_auto_delay_ |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' | sed '1 isource /koolshare/scripts/base.sh' |sed '1 i#!/bin/sh' > /tmp/clash_backup/clash_databackup.sh #自启推迟
	dbus list merlinclash_check |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #功能显示开关等
	dbus list merlinclash_googlehomeswitch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #googlehome
	dbus list merlinclash_cirswitch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #大陆IP绕行
	dbus list merlinclash_dashboard_secret |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #面板密码
	dbus list merlinclash_dashboardswitch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #面板公网访问
	dbus list merlinclash_dnsgoclash |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #代理路由DNS
	dbus list merlinclash_dnsclear |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #自定义DNS清除
	dbus list merlinclash_dnsplan |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #DNS方案
	dbus list merlinclash_host_content1 |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #host编辑区内容
	dbus list merlinclash_hostsel |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #host编辑区内容
	dbus list merlinclash_kcpswitch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #KCP加速开关
	dbus list merlinclash_acl_ |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #自定规则内容
	#dbus list merlinclash_koolproxy_acl |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #KP访问控制内容
	dbus list merlinclash_koolproxy_ |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #KP内容
	dbus list merlinclash_nokpacl_ |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #黑白郎君内容
	dbus list merlinclash_passkpswitch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #外网IP绕过KP
	dbus list merlinclash_tproxymode |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #TPROXY模式
	dbus list merlinclash_unblockmusic_ |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #网易云内容
	dbus list merlinclash_urltestTolerance |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #容差值
	dbus list merlinclash_watchdog |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #看门狗
	dbus list merlinclash_yamlsel |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #当前配置
	dbus list merlinclash_cus |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #自定义端口/自定订阅
	dbus list merlinclash_link |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #订阅链接
	dbus list merlinclash_closeproxy |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #透明代理开关
	dbus list merlinclash_startlog |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #透明代理开关
	dbus list merlinclash_ipv6switch |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #IPV6模式开关
	dbus list merlinclash_iptablessel |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #iptables方案
	dbus list merlinclash_upload |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #上传类
	dbus list merlinclash_linuxver |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #核心版本
	
	if [ "$mcflag" != "HND" ]; then
		dbus list merlinclash_cdn_cbox |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #384 CDN加速订阅开关
	fi
	if [ "$mcflag" == "HND" ]; then
		dbus list merlinclash_dc |  sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' >> /tmp/clash_backup/clash_databackup.sh #DC相关
	fi

	echo_date "备份merlinclash skidpd相关数据完成" >> $LOG_FILE
	echo_date "" >> $LOG_FILE

	echo_date "备份网易云音乐解锁证书" >> $LOG_FILE
	mkdir -p /tmp/clash_backup/UnblockMusic
	cp -rf /koolshare/bin/UnblockMusic/ca.crt /tmp/clash_backup/UnblockMusic/ca.crt 
	cp -rf /koolshare/bin/UnblockMusic/server.key /tmp/clash_backup/UnblockMusic/server.key 
	cp -rf /koolshare/bin/UnblockMusic/server.crt /tmp/clash_backup/UnblockMusic/server.crt

	echo_date "备份KoolProxy证书和规则" >> $LOG_FILE
	mkdir -p /tmp/clash_backup/koolproxy/certs
	mkdir -p /tmp/clash_backup/koolproxy/private
	mkdir -p /tmp/clash_backup/koolproxy/rules
	cp -rf /koolshare/merlinclash/koolproxy/data/certs/ca.crt /tmp/clash_backup/koolproxy/certs/ca.crt 
	cp -rf /koolshare/merlinclash/koolproxy/data/private/ /tmp/clash_backup/koolproxy/
	cp -rf /koolshare/merlinclash/koolproxy/data/rules/ /tmp/clash_backup/koolproxy/

	echo_date "备份merlinclash资料" >> $LOG_FILE
	mkdir -p /tmp/clash_backup/merlinclash/mark
	mkdir -p /tmp/clash_backup/merlinclash/yaml_bak
	mkdir -p /tmp/clash_backup/merlinclash/yaml_basic
	mkdir -p /tmp/clash_backup/merlinclash/yaml_dns
	mkdir -p /tmp/clash_backup/merlinclash/yaml_use
	cp -rf /koolshare/merlinclash/mark/ /tmp/clash_backup/merlinclash/
	cp -rf /koolshare/merlinclash/yaml_bak/ /tmp/clash_backup/merlinclash/
	cp -rf /koolshare/merlinclash/yaml_basic/ /tmp/clash_backup/merlinclash/
	cp -rf /koolshare/merlinclash/yaml_dns/ /tmp/clash_backup/merlinclash/
	cp -rf /koolshare/merlinclash/yaml_use/ /tmp/clash_backup/merlinclash/

	if [ -f "/koolshare/merlinclash/.cache" ]; then
		echo_date "备份merlinclash 节点cache" >> $LOG_FILE
		cp -rf /koolshare/merlinclash/.cache /tmp/clash_backup/merlinclash/
	fi
	if [ "$mcflag" == "HND" ]; then
		echo_date "HND专属：备份自定义ini和list文件" >> $LOG_FILE
		mkdir -p /tmp/clash_backup/merlinclash/custom/ini
		mkdir -p /tmp/clash_backup/merlinclash/custom/list
		cp -rf /koolshare/merlinclash/subconverter/customconfig/* /tmp/clash_backup/merlinclash/custom/ini
		cp -rf /koolshare/merlinclash/subconverter/rules/custom/* /tmp/clash_backup/merlinclash/custom/list
	fi

	echo_date "打包" >> $LOG_FILE
	sleep 1s
	cd /tmp
	tar -czf /tmp/clash_backup.tar.gz -C /tmp clash_backup
	if [ -z "$(cat /tmp/clash_backup.tar.gz)" ]; then
		echo_date "打包结束，但是内容为空，备份出错..."	>> $LOG_FILE
		rm -rf /tmp/clash_backup.tar.gz
		echo BBABBBBC >>  $LOG_FILE
		exit 1
	else
		echo_date "备份打包完成，导出。" >>  $LOG_FILE
		cp -rf /tmp/clash_backup.tar.gz /tmp/upload/clash_backup.tar.gz
	fi
}
clean(){
	[ -n "$name" ] && rm -rf /tmp/clash_backup >/dev/null 2>&1
	rm -rf /tmp/upload/*.tar.gz >/dev/null 2>&1
}

remove_silent(){
	echo_date 先清除已有的相关参数... >> $LOG_FILE
	acls=`dbus list merlinclash_acl_ | cut -d "=" -f 1`
	for acl in $acls
	do
		echo_date 移除$acl 
		dbus remove $acl
	done
	kpacls=`dbus list merlinclash_koolproxy_acl | cut -d "=" -f 1`
	for kpacl in $kpacls
	do
		echo_date 移除$kpacl 
		dbus remove $kpacl
	done
	nokpacls=`dbus list merlinclash_nokpacl_ | cut -d "=" -f 1`
	for nokpacl in $nokpacls
	do
		echo_date 移除$nokpacl 
		dbus remove $nokpacl
	done
	echo_date "--------------------"
}

restore_backup(){
	echo_date 检测到还原文件... >> $LOG_FILE
	echo_date 开始还原操作前先结束clash进程 >> $LOG_FILE
	if [ "$merlinclash_enable" == "1" ]; then
		sh /koolshare/merlinclash/clashconfig.sh stop
	fi
	sleep 1s
	chmod +x /tmp/upload/clash_backup.tar.gz
	rm -rf /tmp/clash_backup
	mv /tmp/upload/clash_backup.tar.gz /tmp
	cd /tmp
	echo_date 尝试解压压缩包 >> $LOG_FILE
	tar -zxvf /tmp/clash_backup.tar.gz >/dev/null 2>&1
	if [ "$?" == "0" ];then
		echo_date 解压完成！ >> $LOG_FILE
	else
		echo_date 解压错误，错误代码："$?"！ >> $LOG_FILE
		echo_date 估计是错误或者不完整的的压缩包！ >> $LOG_FILE
		echo_date 删除相关文件并退出... >> $LOG_FILE
		cd
		clean
		echo BBABBBBC >> $LOG_FILE
		exit 1
	fi
	echo_date 检测jffs分区剩余空间...
	SPACE_AVAL=$(df|grep jffs|head -n 1 | awk '{print $4}')
	SPACE_NEED=$(du -s /tmp/clash_backup | awk '{print $1}')
	if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
		echo_date 当前jffs分区剩余"$SPACE_AVAL" KB,还原备份需要"$SPACE_NEED" KB，空间满足，继续！			
		if [ ! -z "$(cat /tmp/clash_backup/clash_databackup.sh)" ]; then
			echo_date "数据还原脚本内容不为空，执行脚本"	>> $LOG_FILE
			sh /tmp/clash_backup/clash_databackup.sh
		fi
		echo_date "还原koolproxy文件" >> $LOG_FILE
		cp -rf /tmp/clash_backup/koolproxy/certs/ /koolshare/merlinclash/koolproxy/data/
		cp -rf /tmp/clash_backup/koolproxy/private/ /koolshare/merlinclash/koolproxy/data/
		cp -rf /tmp/clash_backup/koolproxy/rules/ /koolshare/merlinclash/koolproxy/data/
		echo_date "还原网易云音乐解锁文件" >> $LOG_FILE
		cp -rf /tmp/clash_backup/UnblockMusic/ /koolshare/bin/
		echo_date "还原MerlinClash文件" >> $LOG_FILE
		cp -rf /tmp/clash_backup/merlinclash/ /koolshare/
		echo_date "创建yaml文件列表" >> $LOG_FILE
		find /koolshare/merlinclash/yaml_bak/  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_bak/yamls.txt
		#创建软链接
		rm -rf /tmp/upload/yamls.txt
		ln -sf /koolshare/merlinclash/yaml_bak/yamls.txt /tmp/upload/yamls.txt
		echo_date "创建host文件列表" >> $LOG_FILE
		find /koolshare/merlinclash/yaml_basic/host/  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_basic/host/hosts.txt
		#创建软链接
		rm -rf /tmp/upload/hosts.txt
		ln -sf /koolshare/merlinclash/yaml_basic/host/hosts.txt /tmp/upload/hosts.txt
		#创建软链接
		if [ -f "/koolshare/merlinclash/yaml_basic/script.yaml" ]; then
			rm -rf /tmp/upload/clash_script.txt
			ln -sf /koolshare/merlinclash/yaml_basic/script.yaml /tmp/upload/clash_script.txt
		fi

		if [ "$mcflag" == "HND" ]; then
			echo_date "HND专属：还原自定义ini和list文件" >> $LOG_FILE
			mkdir -p /koolshare/merlinclash/subconverter/customconfig
			mkdir -p /koolshare/merlinclash/subconverter/rules/custom
			cp -rf /tmp/clash_backup/merlinclash/custom/ini/* /koolshare/merlinclash/subconverter/customconfig
			cp -rf /tmp/clash_backup/merlinclash/custom/list/* /koolshare/merlinclash/subconverter/rules/custom
			echo_date "创建ini/list文件列表" >> $LOG_FILE
			find /koolshare/merlinclash/subconverter/customconfig/  -name "*.ini" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_bak/yamlscus.txt
			find /koolshare/merlinclash/subconverter/rules/custom/  -name "*.list" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_bak/yamlscuslist.txt
			#创建软链接
			ln -sf /koolshare/merlinclash/yaml_bak/yamlscus.txt /tmp/upload/yamlscus.txt
			ln -sf /koolshare/merlinclash/yaml_bak/yamlscuslist.txt /tmp/upload/yamlscuslist.txt
		fi
		echo_date 配置恢复成功！>> $LOG_FILE
	else
		echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 还原备份需要"$SPACE_NEED" KB，空间不足！
		echo_date 退出安装！
		cd
		clean
		echo BBABBBBC
		exit 1
	fi
}
restore_now(){
	[ -f "/tmp/upload/clash_backup.tar.gz" ] && restore_backup
	echo_date 一点点清理工作... >> $LOG_FILE
	rm -rf /tmp/upload/clash_backup.tar.gz
	echo_date 完成！>> $LOG_FILE
}

case $2 in
1)
	backup_conf
	http_response "$1"
	;;
27)
	echo "还原设定" > $LOG_FILE
	http_response "$1"
	remove_silent 
	restore_now 
	echo BBABBBBC >>  $LOG_FILE
	;;
esac