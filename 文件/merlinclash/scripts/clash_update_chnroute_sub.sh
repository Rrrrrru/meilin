#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
uploadpath=/tmp/upload


curl=$(which curl)
wget=$(which wget)

pid_clash=$(pidof clash)

echo_date "开始下载大陆IP白名单..." >> $LOG_FILE

check_file(){
       if [ "$1" == "4" ]; then
              str=$(cat /tmp/ChinaIP.list  | grep payload)
       elif [ "$1" == "6" ]; then
              str=$(cat /tmp/ChinaIPv6.list  | grep payload)
       fi
       if [ -n "$str" ]; then
              echo_date "文件头正确" >> $LOG_FILE
       else
              echo_date "文件错误，请重试" >> $LOG_FILE  
              rm -rf /tmp/ChinaIP.list >/dev/null 2>&1
              sleep 1s
              echo BBABBBBC >> $LOG_FILE  
              exit 1   
       fi
}

update_chnroute(){
       if [ -n "$pid_clash" ]; then
              echo_date "【ipv4】从raw.githubusercontent.com端下载" >> $LOG_FILE
              wget --no-check-certificate --timeout=10 --tries=3 https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv4.yaml -O /tmp/ChinaIP.list
              if [ "$?" == "0" ];then
                     echo_date "检查文件完整性" >> $LOG_FILE
                     if [ -z "$(cat /tmp/ChinaIP.list)" ];then 
                            echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                            wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv4.yaml -O /tmp/ChinaIP.list #>/dev/null 2>&1
                     fi
                     if [ -n "$(cat /tmp/ChinaIP.list)" ];then
                            echo_date "已获取大陆IP白名单文件" >> $LOG_FILE
                     else
                            echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                            wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv4.yaml -O /tmp/ChinaIP.list #>/dev/null 2>&1
                     
                     fi
                     
              else
                     echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                     wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv4.yaml -O /tmp/ChinaIP.list #>/dev/null 2>&1
                     
              fi
       else
              echo_date "从cdn.jsdelivr.net端下载" >> $LOG_FILE
              wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv4.yaml -O /tmp/ChinaIP.list #>/dev/null 2>&1
       fi

       if [ "$?" -eq "0" ] && [ -s "/tmp/ChinaIP.list" ]; then
              echo_date "【ipv4】大陆IP白名单下载成功，检查文件合法性..." >>$LOG_FILE
              check_file "4"
              echo_date "【ipv4】大陆IP白名单下载成功，检查版本是否更新..." >>$LOG_FILE
              cmp -s /tmp/ChinaIP.list /koolshare/merlinclash/yaml_basic/ChinaIP.yaml
              if [ "$?" -ne "0" ]; then
                     echo_date "【ipv4】大陆IP白名单有更新，开始替换旧版本..." >>$LOG_FILE
                     mv /tmp/ChinaIP.list /koolshare/merlinclash/yaml_basic/ChinaIP.yaml >/dev/null 2>&1
                     echo_date "【ipv4】删除下载缓存..." >>$LOG_FILE
                     rm -rf /tmp/ChinaIP.list >/dev/null 2>&1
                     rm -rf /koolshare/res/china_ip_route.ipset >/dev/null 2>&1
                     echo_date "【ipv4】大陆IP白名单规则更新成功！将在下次启动clash时生效。" >>$LOG_FILE
                     sleep 1s
              else
                     echo_date "【ipv4】大陆IP白名单没有更新..." >>$LOG_FILE
                     rm -rf /tmp/ChinaIP.list >/dev/null 2>&1
                     sleep 1s
              fi
       else
              echo_date "【ipv4】大陆IP白名单下载失败。" >>$LOG_FILE
              echo_date "【ipv4】请打开【高级模式】--【代理路由DNS】再试！" >> $LOG_FILE
              rm -rf /tmp/ChinaIP.list >/dev/null 2>&1
              sleep 1s
       fi

       if [ -n "$pid_clash" ]; then
              echo_date "【ipv6】从raw.githubusercontent.com端下载" >> $LOG_FILE
              wget --no-check-certificate --timeout=10 --tries=3 https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv6.yaml -O /tmp/ChinaIPv6.list
              if [ "$?" == "0" ];then
                     echo_date "检查文件完整性" >> $LOG_FILE
                     if [ -z "$(cat /tmp/ChinaIPv6.list)" ];then 
                            echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                            wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv6.yaml -O /tmp/ChinaIPv6.list #>/dev/null 2>&1
                     fi
                     if [ -n "$(cat /tmp/ChinaIPv6.list)" ];then
                            echo_date "已获取大陆IP白名单文件" >> $LOG_FILE
                     else
                            echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                            wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv6.yaml -O /tmp/ChinaIPv6.list #>/dev/null 2>&1
                     
                     fi
                     
              else
                     echo_date "获取大陆IP白名单文件失败！使用CDN地址下载" >> $LOG_FILE
                     wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv6.yaml -O /tmp/ChinaIPv6.list #>/dev/null 2>&1
                     
              fi
       else
              echo_date "从cdn.jsdelivr.net端下载" >> $LOG_FILE
              wget --no-check-certificate --timeout=10 --tries=3 https://cdn.jsdelivr.net/gh/fernvenue/chn-cidr-list@master/ipv6.yaml -O /tmp/ChinaIPv6.list #>/dev/null 2>&1
       fi

       if [ "$?" -eq "0" ] && [ -s "/tmp/ChinaIPv6.list" ]; then
              echo_date "【ipv6】大陆IP白名单下载成功，检查文件合法性..." >>$LOG_FILE
              check_file "6"
              echo_date "【ipv6】大陆IP白名单下载成功，检查版本是否更新..." >>$LOG_FILE
              cmp -s /tmp/ChinaIPv6.list /koolshare/merlinclash/yaml_basic/ChinaIPv6.yaml
              if [ "$?" -ne "0" ]; then
                     echo_date "【ipv6】大陆IP白名单有更新，开始替换旧版本..." >>$LOG_FILE
                     mv /tmp/ChinaIPv6.list /koolshare/merlinclash/yaml_basic/ChinaIPv6.yaml >/dev/null 2>&1
                     echo_date "【ipv6】删除下载缓存..." >>$LOG_FILE
                     rm -rf /tmp/ChinaIPv6.list >/dev/null 2>&1
                     rm -rf /koolshare/res/china_ip_route6.ipset >/dev/null 2>&1
                     echo_date "【ipv6】大陆IP白名单规则更新成功！将在下次启动clash时生效。" >>$LOG_FILE
                     sleep 1s
                     echo BBABBBBC >> $LOG_FILE
              else
                     echo_date "【ipv6】大陆IP白名单没有更新，停止继续操作..." >>$LOG_FILE
                     rm -rf /tmp/ChinaIPv6.list >/dev/null 2>&1
                     sleep 1s
                     echo BBABBBBC >> $LOG_FILE
              fi
       else
              echo_date "【ipv6】大陆IP白名单下载失败。" >>$LOG_FILE
              echo_date "【ipv6】请打开【高级模式】--【代理路由DNS】再试！" >> $LOG_FILE
              rm -rf /tmp/ChinaIPv6.list >/dev/null 2>&1
              sleep 1s
              echo BBABBBBC >> $LOG_FILE
       fi
}
case $1 in
down)
	update_chnroute >> $LOG_FILE 2>&1
	echo BBABBBBC >> $LOG_FILE
	;;
esac
