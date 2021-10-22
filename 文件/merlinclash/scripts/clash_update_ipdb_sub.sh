#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
uploadpath=/tmp/upload


curl=$(which curl)
wget=$(which wget)

ipdb_url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=oeEqpP5QI21N&suffix=tar.gz"
ipip_url="https://cdn.jsdelivr.net/gh/alecthw/mmdb_china_ip_list@release/Country.mmdb"
hip_url="https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/Country.mmdb"
ls_url="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
ls_cdn="https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"

get(){
	a=$(echo $(dbus get $1))
	a=$(echo $(dbus get $1))
	echo $a
}
mcgt=$(get merlinclash_geoip_type)
mcud=$(get merlinclash_updata_date)
update_ipdb(){
       if [ "$mcgt" == "maxmind" ]; then
       echo_date "下载数据库来源为：$mcgt" >> $LOG_FILE
       if [ "x$wget" != "x" ] && [ -x $wget ]; then
              command="$wget --no-check-certificate --tries=3 $ipdb_url -O $uploadpath/ipdb.tar.gz"
       elif [ "x$curl" != "x" ] && [ test -x $curl ]; then
              command="$curl -k --compressed $ipdb_url -o $uploadpath/ipdb.tar.gz"
       else
              echo_date "没有找到 wget 或 curl，无法更新 IP 数据库！" >> $LOG_FILE
              echo BBABBBBC >> $LOG_FILE
              exit 1
       fi
       echo_date "开始下载最新 IP 数据库..." >> $LOG_FILE
       $command

       if [ ! -f "$uploadpath/ipdb.tar.gz" ]; then
              echo_date "下载 IP 数据库失败！退出更新" >> $LOG_FILE
              echo BBABBBBC >> $LOG_FILE
              exit 1
       else
              echo_date "下载完成，开始解压" >> $LOG_FILE
              mkdir -p $uploadpath/ipdb
              tar zxvf $uploadpath/ipdb.tar.gz -C $uploadpath/ipdb

              chmod 644 $uploadpath/ipdb/GeoLite2-Country_*/*
              version=$(ls $uploadpath/ipdb | grep 'GeoLite2-Country' | sed "s|GeoLite2-Country_||g")
              echo_date 检测jffs分区剩余空间... >> $LOG_FILE
              SPACE_AVAL=$(df|grep jffs|head -n 1  | awk '{print $4}')
              SPACE_NEED=$(du -s $uploadpath/ipdb/GeoLite2-Country_*/GeoLite2-Country.mmdb | awk '{print $1}')
              if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
                     echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间满足，继续安装！>> $LOG_FILE

                     echo_date "更新版本" >> $LOG_FILE
                     cp -rf $uploadpath/ipdb/GeoLite2-Country_*/GeoLite2-Country.mmdb /koolshare/merlinclash/Country.mmdb

                     echo_date "更新 IP 数据库至 $version 版本" >> $LOG_FILE
                     dbus set merlinclash_ipdb_version=$version

                     echo_date "清理临时文件..." >> $LOG_FILE
                     rm -rf $uploadpath/ipdb.tar.gz
                     rm -rf $uploadpath/ipdb

                     echo_date "IP 数据库更新完成！" >> $LOG_FILE
                     echo_date "注意！新版 IP 数据库将在下次启动 Clash 时生效！" >> $LOG_FILE
                     sleep 1
              else
                     echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间不足！>> $LOG_FILE
                     echo_date 退出安装！>> $LOG_FILE
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              fi
       fi
       fi

       if [ "$mcgt" == "ipip" ] ; then
              echo_date "下载数据库来源为：$mcgt" >> $LOG_FILE
              if [ "x$wget" != "x" ] && [ -x $wget ]; then
              command="$wget --no-check-certificate --tries=3 $ipip_url -O $uploadpath/Country.mmdb"
              elif [ "x$curl" != "x" ] && [ test -x $curl ]; then
                     command="$curl -k --compressed $ipip_url -o $uploadpath/Country.mmdb"
              else
                     echo_date "没有找到 wget 或 curl，无法更新 IP 数据库！" >> $LOG_FILE
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              fi
              echo_date "开始下载最新 IP 数据库..." >> $LOG_FILE
              $command    

              if [ ! -f "$uploadpath/Country.mmdb" ]; then
                     echo_date "下载 IP 数据库失败！退出更新" >> $LOG_FILE
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              else  
                     echo_date "下载完成，开始替换" >> $LOG_FILE
                     mcud=$(get merlinclash_updata_date)
                     version=$mcud
                     echo_date 检测jffs分区剩余空间... >> $LOG_FILE
                     SPACE_AVAL=$(df|grep jffs|head -n 1  | awk '{print $4}')
                     SPACE_NEED=$(du -s $uploadpath/Country.mmdb | awk '{print $1}')
                     if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间满足，继续安装！>> $LOG_FILE
                            echo_date "更新版本" >> $LOG_FILE
                            cp -rf $uploadpath/Country.mmdb /koolshare/merlinclash/Country.mmdb

                            echo_date "更新 IP 数据库至 $version 版本" >> $LOG_FILE
                            dbus set merlinclash_ipdb_version=$version

                            echo_date "清理临时文件..." >> $LOG_FILE
                            rm -rf $uploadpath/Country.mmdb
                            

                            echo_date "IP 数据库更新完成！" >> $LOG_FILE
                            echo_date "注意！新版 IP 数据库将在下次启动 Clash 时生效！" >> $LOG_FILE
                            sleep 1
                     else
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间不足！>> $LOG_FILE
                            echo_date 退出安装！>> $LOG_FILE
                            echo BBABBBBC >> $LOG_FILE
                            exit 1
                     fi
              fi
       fi

       if [ "$mcgt" == "Hackl0us" ] ; then
              echo_date "下载数据库来源为：$mcgt" >> $LOG_FILE
              if [ "x$wget" != "x" ] && [ -x $wget ]; then
              command="$wget --no-check-certificate --tries=3 $hip_url -O $uploadpath/Country.mmdb"
              elif [ "x$curl" != "x" ] && [ test -x $curl ]; then
                     command="$curl -k --compressed $hip_url -o $uploadpath/Country.mmdb"
              else
                     echo_date "没有找到 wget 或 curl，无法更新 IP 数据库！" >> $LOG_FILE
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              fi
              echo_date "开始下载最新 IP 数据库..." >> $LOG_FILE
              $command >> $LOG_FILE   

              if [ ! -f "$uploadpath/Country.mmdb" ]; then
                     echo_date "下载 IP 数据库失败！退出更新" >> $LOG_FILE
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              else  
                     echo_date "下载完成，开始替换" >> $LOG_FILE
                     version=$mcud
                     echo_date 检测jffs分区剩余空间... >> $LOG_FILE
                     SPACE_AVAL=$(df|grep jffs|head -n 1  | awk '{print $4}')
                     SPACE_NEED=$(du -s $uploadpath/Country.mmdb | awk '{print $1}')
                     if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间满足，继续安装！>> $LOG_FILE
                            echo_date "更新版本" >> $LOG_FILE
                            cp -rf $uploadpath/Country.mmdb /koolshare/merlinclash/Country.mmdb

                            echo_date "更新 IP 数据库至 $version 版本" >> $LOG_FILE
                            dbus set merlinclash_ipdb_version=$version

                            echo_date "清理临时文件..." >> $LOG_FILE
                            rm -rf $uploadpath/Country.mmdb
                            

                            echo_date "IP 数据库更新完成！" >> $LOG_FILE
                            echo_date "注意！新版 IP 数据库将在下次启动 Clash 时生效！" >> $LOG_FILE
                            sleep 1
                     else
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间不足！>> $LOG_FILE
                            echo_date 退出安装！>> $LOG_FILE
                            echo BBABBBBC >> $LOG_FILE
                            exit 1
                     fi
              fi
       fi

       if [ "$mcgt" == "Loyalsoldier" ] ; then
              echo_date "下载数据库来源为：$mcgt" 
              if [ "x$wget" != "x" ] && [ -x $wget ]; then
              #command="$wget --no-check-certificate --tries=3 $ls_url -O $uploadpath/Country.mmdb"
              command="$wget --no-check-certificate --tries=3 --timeout=10 $ls_url -O $uploadpath/Country.mmdb"
              elif [ "x$curl" != "x" ] && [ test -x $curl ]; then
                     command="$curl -k --compressed $ls_url -o $uploadpath/Country.mmdb"
              else
                     echo_date "没有找到 wget 或 curl，无法更新 IP 数据库！" 
                     echo BBABBBBC >> $LOG_FILE
                     exit 1
              fi
              echo_date "开始下载最新 IP 数据库..." 
              $command

              if [ "$?" == "0" ];then
                     if [ -f "$uploadpath/Country.mmdb" ]; then  
                            echo_date "数据库下载成功，但是否完整还需通过日志人为判断"
                     else
                            echo_date "数据库下载失败，从CDN地址下载"
                            command="$wget --no-check-certificate --tries=3 --timeout=10 $ls_cdn -O $uploadpath/Country.mmdb"
                            $command
                     fi
              fi
              if [ "$?" -eq "0" ] && [ -f "$uploadpath/Country.mmdb" ]; then 
                     echo_date "下载完成，开始替换" >> $LOG_FILE
                     version=$mcud
                     echo_date 检测jffs分区剩余空间... >> $LOG_FILE
                     SPACE_AVAL=$(df|grep jffs|head -n 1  | awk '{print $4}')
                     SPACE_NEED=$(du -s $uploadpath/Country.mmdb | awk '{print $1}')
                     if [ "$SPACE_AVAL" -gt "$SPACE_NEED" ];then
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间满足，继续安装！>> $LOG_FILE
                            echo_date "更新版本" >> $LOG_FILE
                            cp -rf $uploadpath/Country.mmdb /koolshare/merlinclash/Country.mmdb

                            echo_date "更新 IP 数据库至 $version 版本" >> $LOG_FILE
                            dbus set merlinclash_ipdb_version=$version

                            echo_date "清理临时文件..." >> $LOG_FILE
                            rm -rf $uploadpath/Country.mmdb
                            

                            echo_date "IP 数据库更新完成！" >> $LOG_FILE
                            echo_date "注意！新版 IP 数据库将在下次启动 Clash 时生效！" >> $LOG_FILE
                            sleep 1
                     else
                            echo_date 当前jffs分区剩余"$SPACE_AVAL" KB, 数据库需要"$SPACE_NEED" KB，空间不足！>> $LOG_FILE
                            echo_date 退出安装！>> $LOG_FILE
                            echo BBABBBBC >> $LOG_FILE
                            exit 1
                     fi
              else
                     echo_date "数据库下载失败，退出更新"
                     exit 1       
              fi

       fi
}
case $1 in
down)
	update_ipdb >> $LOG_FILE 2>&1
	echo BBABBBBC >> $LOG_FILE
	;;
esac