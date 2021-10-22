#! /bin/sh

source /koolshare/scripts/base.sh
eval $(dbus export merlinclash)
#alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
ROG_86U=0
BUILDNO=$(nvram get buildno)
EXT_NU=$(nvram get extendno)
EXT_NU=$(echo ${EXT_NU%_*} | grep -Eo "^[0-9]{1,10}$" )
[ -z "${EXT_NU}" ] && EXT_NU="0"
odmpid=$(nvram get odmpid)
productid=$(nvram get productid)
[ -n "${odmpid}" ] && MODEL="${odmpid}" || MODEL="${productid}"
LINUX_VER=$(uname -r|awk -F"." '{print $1$2}')
mkdir -p /koolshare/merlinclash
mkdir -p /tmp/upload
sleep 2s
get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
me=$(get merlinclash_enable)
# 获取固件类型
_get_type() {
	local FWTYPE=$(nvram get extendno|grep koolshare)
	if [ -d "/koolshare" ];then
		if [ -n $FWTYPE ];then
			echo "koolshare官改固件"
		else
			echo "koolshare梅林改版固件"
		fi
	else
		if [ "$(uname -o|grep Merlin)" ];then
			echo "梅林原版固件"
		else
			echo "华硕官方固件"
		fi
	fi
}

exit_install(){
	local state=$1
	case $state in
		1)
			echo_date "本插件适用于适用于【koolshare 梅林改/官改 hnd/axhnd/axhnd.675x】固件平台，你的固件平台不能安装！！！"
			echo_date "本插件支持机型/平台：https://github.com/koolshare/rogsoft#rogsoft"
			echo_date "退出安装！"
			rm -rf /tmp/${module}* >/dev/null 2>&1
			exit 1
			;;
		0|*)
			rm -rf /tmp/${module}* >/dev/null 2>&1
			exit 0
			;;
	esac
}

# 判断路由架构和平台
case $(uname -m) in
	aarch64)
		if [ "$(uname -o|grep Merlin)" -a -d "/koolshare" ];then
			echo_date 机型：$MODEL $(_get_type) 符合安装要求，开始安装插件！
		else
			exit_install 1
		fi
		;;
	#armv7l)
	#	if [ "$MODEL" == "TUF-AX3000" -o "$MODEL" == "RT-AX82U" ] && [ -d "/koolshare" ];then
	#		echo_date 机型：$MODEL $(_get_type) 符合安装要求，开始安装插件！
	#	else
	#		exit_install 1
	#	fi
	#	;;
	*)
		exit_install 1
	;;
esac

if [ -n "$(nvram get extendno | grep koolshare)" -a "$(nvram get productid)" == "RT-AC86U" -a "${EXT_NU}" -lt "81918" -a "${BUILDNO}" != "386" ];then
	ROG_86U=1
fi

# 判断固件需要什么UI
if [ "${MODEL}" == "GT-AC5300" -o "${MODEL}" == "GT-AX11000" -o "${MODEL}" == "GT-AX11000_BO4"  -o "$ROG_86U" == "1" ];then
	# 官改固件，骚红皮肤
	ROG=1
fi

#if [ "$MODEL" == "TUF-AX3000" ];then
#	# 官改固件，橙色皮肤
#	TUF=1
#fi

#if [ -n "$(ls /koolshare/ss/postscripts/P*.sh 2>/dev/null)" ];then
#	echo_date 备份触发脚本!
#	find /koolshare/ss/postscripts -name "P*.sh" | xargs -i mv {} -f /tmp/ss_backup
#fi

# 检测储存空间是否足够
echo_date 检测jffs分区剩余空间...
SPACE_AVAL=$(df|grep jffs|head -n 1  | awk '{print $4}')
SPACE_NEED=$(du -s /tmp/merlinclash | awk '{print $1}')
if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
	echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 插件安装需要"$SPACE_NEED" KB，空间满足，继续安装！
	#升级前先删除无关文件,保留已上传配置文件
	# 先关闭clash
	if [ "$me" == "1" ];then
		echo_date 先关闭clash插件，保证文件更新成功!
		[ -f "/koolshare/merlinclash/clashconfig.sh" ] && sh /koolshare/merlinclash/clashconfig.sh stop
	fi
	echo_date 清理旧文件,保留已上传配置文件
	rm -rf /koolshare/merlinclash/Country.mmdb
	rm -rf /koolshare/merlinclash/*.yaml
	rm -rf /koolshare/merlinclash/*.txt
	rm -rf /koolshare/merlinclash/clashconfig.sh
	rm -rf /koolshare/merlinclash/version
	rm -rf /koolshare/merlinclash/yaml_basic/
	rm -rf /koolshare/merlinclash/yaml_dns/
	rm -rf /koolshare/merlinclash/dashboard/
	rm -rf /koolshare/bin/clash
	rm -rf /koolshare/bin/yq
	rm -rf /koolshare/bin/jq_c
	rm -rf /koolshare/bin/haveged_c
	#------网易云内容-----------
	rm -rf /koolshare/bin/UnblockNeteaseMusic #二进制
	rm -rf /koolshare/bin/UnblockMusic #文件夹
	#------网易云内容-----------
	#------subconverter--------
	[ -L "/koolshare/bin/subconverter" ] && rm -rf /koolshare/bin/subconverter
	rm -rf /koolshare/merlinclash/subconverter
	#------subconverter--------
	#------koolproxy--------
	[ -L "/koolshare/bin/koolproxy" ] && rm -rf /koolshare/bin/koolproxy
	rm -rf /koolshare/merlinclash/koolproxy
	#------koolproxy--------
	rm -rf /tmp/upload/*.yaml
	rm -rf /koolshare/webs/Module_merlinclash*
	rm -rf /koolshare/res/icon-merlinclash.png
	rm -rf /koolshare/res/clash-kcp.jpg
	rm -rf /koolshare/res/clash*
	rm -rf /koolshare/res/china_ip_route.ipset
	rm -rf /koolshare/res/china_ip_route6.ipset
	rm -rf /koolshare/scripts/clash*

	find /koolshare/init.d/ -name "*clash.sh" | xargs rm -rf
	cd /koolshare/bin && mkdir -p UnblockMusic && cd
	cd /koolshare/merlinclash && mkdir -p dashboard && cd
	cd /koolshare/merlinclash && mkdir -p yaml_basic && cd
	cd /koolshare/merlinclash/yaml_basic && mkdir -p host && cd
	cd /koolshare/merlinclash && mkdir -p yaml_dns && cd
	cd /koolshare/merlinclash && mkdir -p yaml_bak && cd
	cd /koolshare/merlinclash && mkdir -p yaml_use && cd
	cd /koolshare/merlinclash && mkdir -p subconverter && cd
	#增加koolproxy文件夹
	cd /koolshare/merlinclash && mkdir -p koolproxy && cd
	echo_date 开始复制文件！
	cd /tmp

	echo_date 复制相关二进制文件！此步时间可能较长！
	cp -rf /tmp/merlinclash/clash/clash /koolshare/bin/
	cp -rf /tmp/merlinclash/clash/yq /koolshare/bin/
	cp -rf /tmp/merlinclash/clash/jq_c /koolshare/bin/
	cp -rf /tmp/merlinclash/clash/haveged_c /koolshare/bin/
	#------网易云内容-----------
	cp -rf /tmp/merlinclash/UnblockMusic/* /koolshare/bin/UnblockMusic/	
	#------网易云内容-----------

	#------subconverter--------
	cp -rf /tmp/merlinclash/subconverter/* /koolshare/merlinclash/subconverter/
	[ ! -L "/koolshare/bin/subconverter" ] && ln -sf /koolshare/merlinclash/subconverter/subconverter /koolshare/bin/subconverter	
	#------subconverter--------

	#------koolproxy--------
	cp -rf /tmp/merlinclash/koolproxy/* /koolshare/merlinclash/koolproxy/
	#------koolproxy--------

	cp -rf /tmp/merlinclash/clash/Country.mmdb /koolshare/merlinclash/
	cp -rf /tmp/merlinclash/clash/clashconfig.sh /koolshare/merlinclash/
	cp -rf /tmp/merlinclash/version /koolshare/merlinclash/

	cp -rf /tmp/merlinclash/yaml_basic/* /koolshare/merlinclash/yaml_basic/
	cp -rf /tmp/merlinclash/yaml_dns/* /koolshare/merlinclash/yaml_dns/
	cp -rf /tmp/merlinclash/dashboard/* /koolshare/merlinclash/dashboard/

	echo_date 复制相关的脚本文件！
	cp -rf /tmp/merlinclash/scripts/* /koolshare/scripts/
	cp -rf /tmp/merlinclash/install.sh /koolshare/scripts/merlinclash_install.sh
	cp -rf /tmp/merlinclash/uninstall.sh /koolshare/scripts/uninstall_merlinclash.sh

	echo_date 复制相关的网页文件！
	cp -rf /tmp/merlinclash/webs/* /koolshare/webs/
	cp -rf /tmp/merlinclash/res/* /koolshare/res/
	  if [ "$ROG" == "1" ];then
	        cp -rf /tmp/merlinclash/rog/res/merlinclash.css /koolshare/res/
      fi
#      if [ "$TUF" == "1" ];then
#	        sed -i 's/3e030d/3e2902/g;s/91071f/92650F/g;s/680516/D0982C/g;s/cf0a2c/c58813/g;s/700618/74500b/g;s/530412/92650F/g' /tmp/merlinclash/rog/res/merlinclash.css >/dev/null 2>&1
#	        cp -rf /tmp/merlinclash/rog/res/merlinclash.css /koolshare/res/
#      fi

	echo_date 为新安装文件赋予执行权限...
	chmod 755 /koolshare/bin/clash
	chmod 755 /koolshare/bin/yq
	chmod 755 /koolshare/bin/jq_c
	chmod 755 /koolshare/bin/haveged_c
	chmod 755 /koolshare/bin/UnblockMusic/*
	chmod 755 /koolshare/merlinclash/Country.mmdb
	chmod 755 /koolshare/merlinclash/yaml_basic/*
	chmod 755 /koolshare/merlinclash/yaml_dns/*
	chmod 755 /koolshare/merlinclash/subconverter/*
	chmod 755 /koolshare/merlinclash/koolproxy/*
	chmod 755 /koolshare/merlinclash/*
	chmod 755 /koolshare/scripts/clash*


	echo_date "创建自启脚本软链接！"
	[ -L "/koolshare/init.d/S99merlinclash.sh" ] && rm -rf /koolshare/init.d/S99merlinclash.sh && ln -sf /koolshare/merlinclash/clashconfig.sh /koolshare/init.d/S99merlinclash.sh
	[ -L "/koolshare/init.d/N99merlinclash.sh" ] && rm -rf /koolshare/init.d/N99merlinclash.sh && ln -sf /koolshare/merlinclash/clashconfig.sh /koolshare/init.d/N99merlinclash.sh
	[ ! -L "/koolshare/init.d/S99merlinclash.sh" ]  && ln -sf /koolshare/merlinclash/clashconfig.sh /koolshare/init.d/S99merlinclash.sh
	[ ! -L "/koolshare/init.d/N99merlinclash.sh" ]  && ln -sf /koolshare/merlinclash/clashconfig.sh /koolshare/init.d/N99merlinclash.sh

	echo_date "创建dns文件软链接！"
	[ -L "/tmp/upload/dns_redirhost.txt" ] && rm -rf /tmp/upload/dns_redirhost.txt && ln -sf /koolshare/merlinclash/yaml_dns/redirhost.yaml /tmp/upload/dns_redirhost.txt
	[ -L "/tmp/upload/dns_fakeip.txt" ] && rm -rf /tmp/upload/dns_fakeip.txt && ln -sf /koolshare/merlinclash/yaml_dns/fakeip.yaml /tmp/upload/dns_fakeip.txt

	[ ! -L "/tmp/upload/dns_redirhost.txt" ] && ln -sf /koolshare/merlinclash/yaml_dns/redirhost.yaml /tmp/upload/dns_redirhost.txt
	[ ! -L "/tmp/upload/dns_fakeip.txt" ] && ln -sf /koolshare/merlinclash/yaml_dns/fakeip.yaml /tmp/upload/dns_fakeip.txt

	# 离线安装时设置软件中心内储存的版本号和连接
	
	echo_date 清空冗余值
	dbus remove merlinclash_proxygroup_version
	dbus remove merlinclash_proxygame_version
	dbus remove merlinclash_scrule_version
	dbus remove merlinclash_version_local
	dbus remove merlinclash_patch_version
	dbus remove merlinclash_dashboard_secret
	dbus remove merlinclash_bypassmode
	dbus remove merlinclash_dc_ss
	dbus remove merlinclash_dc_v2
	dbus remove merlinclash_dc_trojan
	dbus remove merlinclash_links
	dbus remove merlinclash_links2
	dbus remove merlinclash_kcp_param_2
	dbus remove merlinclash_dc_name
	dbus remove merlinclash_dc_passwd
	dbus remove merlinclash_dc_token
	dbus remove merlinclash_dnsedit_tag
	dbus remove merlinclash_dns_edit_content1
	dbus remove merlinclash_host_content1
	dbus remove merlinclash_host_content1_tmp
	dbus remove softcenter_module_merlinclash_install
	dbus remove softcenter_module_merlinclash_version
	dbus remove merlinclash_mark_MD51
	acls=`dbus list merlinclash_acl_ | cut -d "=" -f 1`
	for acl in $acls
	do
		#echo_date 移除$acl 
		dbus remove $acl
	done
	devs=`dbus list merlinclash_device_ | cut -d "=" -f 1`
	for dev in $devs
	do
		#echo_date 移除$acl 
		dbus remove $dev
	done
	wls=`dbus list merlinclash_whitelist_ | cut -d "=" -f 1`
	for wl in $wls
	do
		dbus remove $wl
	done
	ips=`dbus list merlinclash_ipport_ | cut -d "=" -f 1`
	for ip in $ips
	do
		dbus remove $ip
	done
	kps=`dbus list merlinclash_koolproxy_ | cut -d "=" -f 1`
	for kp in $kps
	do
		dbus remove $kp
	done
	kpas=`dbus list merlinclash_kpacl_ | cut -d "=" -f 1`
	for kpa in $kpas
	do
		dbus remove $kpa
	done
	nokpas=`dbus list merlinclash_nokpacl_ | cut -d "=" -f 1`
	for nokpa in $nokpas
	do
		dbus remove $nokpa
	done
	echo_date 设置相关参数初始值！
	CUR_VERSION=$(cat /koolshare/merlinclash/version)
	[ ! -L "/koolshare/bin/koolproxy" ] && ln -sf /koolshare/merlinclash/koolproxy/koolproxy /koolshare/bin/koolproxy	
	kpversion="$(/koolshare/merlinclash/koolproxy/koolproxy -v)"
	if [ -n "$kpversion" ]; then
		kpv="$kpversion"		
	else
		kpv="null"
	fi
	echo_date "数据初始化"
	dbus set merlinclash_koolproxy_version=$kpv
	dbus set merlinclash_version_local="$CUR_VERSION"
	dbus set merlinclash_patch_version="004" #
	dbus set softcenter_module_merlinclash_install="1"
	dbus set softcenter_module_merlinclash_version="$CUR_VERSION"
	dbus set softcenter_module_merlinclash_title="Merlin Clash [3in1]"
	dbus set softcenter_module_merlinclash_description="Merlin Clash:一个基于规则的代理程序，支持多种协议~"
	#dbus set merlinclash_proxygroup_version="2021011601"
	#dbus set merlinclash_proxygame_version="2020070101"
	dbus set merlinclash_scrule_version="2021101601"
	dbus set merlinclash_dnsedit_tag="redirhost"
	dbus set merlinclash_bypassmode="1"
	dbus set merlinclash_dc_name=""
	dbus set merlinclash_dc_passwd=""
	dbus set merlinclash_dc_token=""
	dbus set merlinclash_flag="HND"
	dbus set merlinclash_kpacl_default_mode="1"
	dbus set merlinclash_mark_MD51=""
	dbus set merlinclash_check_clashimport=1 #导入CLASH
	dbus set merlinclash_check_sclocal=1	#SUBC/ACL转换
	dbus set merlinclash_check_ssimport=1	#导入科学节点
	dbus set merlinclash_check_upcusrule=0	#上传自定订阅
	dbus set merlinclash_check_xiaobai=1	#小白一键订阅
	dbus set merlinclash_check_yamldown=1 #YAML下载
	dbus set merlinclash_check_kcp=0	#KCP加速
	dbus set merlinclash_check_kp=0		#护网大师
	dbus set merlinclash_check_noipt=0 	#透明代理
	dbus set merlinclash_check_aclrule=0 	#自定规则
	dbus set merlinclash_check_cdns=0 	#DNS编辑区
	dbus set merlinclash_check_cdns=0 	#HOST编辑区
	dbus set merlinclash_check_scriptedit=0 	#script编辑区
	dbus set merlinclash_check_controllist=0 	#黑白郎君
	dbus set merlinclash_check_cusport=0 	#自定义端口
	dbus set merlinclash_check_dlercloud=0 	#DC用户
	dbus set merlinclash_check_tproxy=0 	#TPROXY
	dbus set merlinclash_check_unblock=0 	#云村解锁
	dbus set merlinclash_cirswitch=1 #大陆绕行IP 强制打开
	
	dbus set merlinclash_links=" "
	dbus set merlinclash_links2=" "
	dbus set merlinclash_links3=" "
	dbus set merlinclash_dnsclear="1"
	dbus set merlinclash_linuxver="$LINUX_VER"
	dbus set merlinclash_tproxymode="closed"
	dbus set merlinclash_ipv6switch="0"
	dbus set merlinclash_iptablessel="fangan1"

	merlinclash_clash_version_tmp=$(/koolshare/bin/clash -v 2>/dev/null | head -n 1 | cut -d " " -f2)
	if [ -n "$merlinclash_clash_version_tmp" ]; then
		mcv="$merlinclash_clash_version_tmp"		
	else
		mcv="null"
	fi
	dbus set merlinclash_clash_version="$mcv"
	#提取配置认证码
	secret=$(cat /koolshare/merlinclash/yaml_basic/head.yaml | awk '/secret:/{print $2}' | sed 's/"//g')
	dbus set merlinclash_dashboard_secret="$secret"

	echo_date 一点点清理工作...
	rm -rf /tmp/clash* >/dev/null 2>&1

	echo_date clash插件安装成功！
	#yaml不为空则复制文件 然后生成yamls.txt
	dir=/koolshare/merlinclash/yaml_bak
	a=$(ls $dir | wc -l)
	if [ $a -gt 0 ]
	then
		cp -rf /koolshare/merlinclash/yaml_bak/*.yaml  /koolshare/merlinclash/yaml_use/
	fi
	
		
	#生成新的txt文件

	rm -rf /koolshare/merlinclash/yaml_bak/yamls.txt
	echo_date "初始化yaml文件列表"
	find /koolshare/merlinclash/yaml_bak  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_bak/yamls.txt
	#创建软链接
	ln -sf /koolshare/merlinclash/yaml_bak/yamls.txt /tmp/upload/yamls.txt
	#
	echo_date "初始化host文件列表"
	find /koolshare/merlinclash/yaml_basic/host  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' > /koolshare/merlinclash/yaml_basic/host/hosts.txt
	#创建软链接
	ln -sf /koolshare/merlinclash/yaml_basic/host/hosts.txt /tmp/upload/hosts.txt
	dbus set merlinclash_hostsel="default"

	echo_date "初始化配置文件处理完成"

	if [ "$me" == "1" ];then
		echo_date 重启clash插件！
		sh /koolshare/scripts/clash_config.sh start start
	fi

	echo_date 更新完毕，请等待网页自动刷新！
else
	echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 插件安装需要"$SPACE_NEED" KB，空间不足！
	echo_date 退出安装！
	exit 1
fi

