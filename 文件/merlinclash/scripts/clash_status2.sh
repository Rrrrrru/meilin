#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'

pid_clash=$(pidof clash)
#pid_watchdog=$(ps | grep clash_watchdog.sh | grep -v grep | awk '{print $1}')
pid_watchdog=$(cru l | grep "clash_watchdog")
date=$(echo_date)
get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
yamlname=$(get merlinclash_yamlsel)
yamlpath=/koolshare/merlinclash/yaml_use/$yamlname.yaml
lan_ipaddr=$(nvram get lan_ipaddr)
board_port="9990"

starttime=$(get merlinclash_clashstarttime)

if [ -n "$pid_clash" ]; then
    text1="<span style='color: #6C0'>$date Clash 进程运行正常！(PID: $pid_clash)</span>"
    text3="<span style='color: #6C0'>【Clash本次启动时间】：$starttime</span>"
else
    text1="<span style='color: red'>$date Clash 进程未在运行！</span>"
    text3="<span style='color: red'>$date Clash 进程未在运行！</span>"
fi

if [ -n "$pid_watchdog" ]; then
    text2="<span style='color: #6C0'>$date Clash 看门狗运行正常！</span>"
else
    text2="<span style='color: gold'>$date Clash 看门狗未在运行！</span>"
fi


http_response "$text1@$text2@$text3"
