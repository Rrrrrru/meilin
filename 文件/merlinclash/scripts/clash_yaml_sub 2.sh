#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt
lan_ip=$(nvram get lan_ipaddr)
uploadpath=/tmp/upload/
fp=/koolshare/merlinclash/yaml_bak
rm -rf /tmp/upload/clash_error.log
rm -rf /tmp/upload/dns_read_error.log
name=$(find $uploadpath  -name "*.yaml" |sed 's#.*/##')
yaml_tmp=/tmp/upload/$name
head_tmp=/koolshare/merlinclash/yaml_basic/head.yaml

#读取原配置mode值
mode=$(cat $yaml_tmp | awk -F: '/^mode/{print $2}'| xargs echo -n)
echo_date "yaml文件【后台处理ing】，请在日志页面看到完成后，再启动Clash！！！" >> $LOG_FILE
sleep 2s
#去注释
echo_date "文件格式标准化" >> $LOG_FILE
#将所有DNS都转化成dns
sed -i 's/DNS/dns/g' $yaml_tmp
#老格式处理
#当文件存在Proxy:开头的行数，将Proxy: ~替换成空格
para0=$(sed -n '/^\.\.\./p' $yaml_tmp)
if [ -n "$para0" ] ; then
    sed -i 's/^\.\.\.//g' $yaml_tmp
fi
para0=$(sed -n '/^\-\-\-/p' $yaml_tmp)
if [ -n "$para0" ] ; then
    sed -i 's/^\-\-\-//g' $yaml_tmp
fi
#当文件存在Proxy:开头的行数，将Proxy: ~替换成空格
para1=$(sed -n '/^Proxy: ~/p' $yaml_tmp)
if [ -n "$para1" ] ; then
    sed -i 's/Proxy: ~//g' $yaml_tmp
fi

para2=$(sed -n '/^Proxy Group: ~/p' $yaml_tmp)
#当文件存在Proxy Group:开头的行数，将Proxy Group: ~替换成空格
if [ -n "$para2" ] ; then
    sed -i 's/Proxy Group: ~//g' $yaml_tmp
fi
#当文件存在奇葩声明，删除，重写
pg_line=$(grep -n "Proxy Group" $yaml_tmp | awk -F ":" '{print $1}' )
if [ -n "$pg_line" ] ; then
    sed -i "$pg_line d" $yaml_tmp
    sed -i "$pg_line i proxy-groups:" $yaml_tmp
fi
para3=$(sed -n '/Rule: ~/p' $yaml_tmp)
#当文件存在Rule:开头的行数，将Rule: ~替换成空格
if [ -n "$para3" ] ; then
    echo_date "将Rule:替换成rules:" >> $LOG_FILE
    sed -i 's/Rule: ~//g' $yaml_tmp
fi
#当文件存在Proxy:开头的行数，将Proxy:替换成proxies:
para1=$(sed -n '/^Proxy:/p' $yaml_tmp)
if [ -n "$para1" ] ; then
    sed -i 's/Proxy:/proxies:/g' $yaml_tmp
fi

para2=$(sed -n '/^Proxy Group:/p' $yaml_tmp)
#当文件存在Proxy Group:开头的行数，将Proxy Group:替换成proxy-groups:
if [ -n "$para2" ] ; then
    sed -i 's/Proxy Group:/proxy-groups:/g' $yaml_tmp
fi

para3=$(sed -n '/Rule:/p' $yaml_tmp)
#当文件存在Rule:开头的行数，将Rule:替换成rules:
if [ -n "$para3" ] ; then
    sed -i 's/Rule:/rules:/g' $yaml_tmp
fi

para4=$(sed -n '/^mixed-port:/p' $yaml_tmp)
#当文件存在mixed-port:开头的行数，将mixed-port:替换成port:
if [ -n "$para4" ] ; then
    sed -i 's/^mixed-port:/port:/g' $yaml_tmp
fi

proxies_line=$(cat $yaml_tmp | grep -n "^proxies:" | awk -F ":" '{print $1}')
#20200902+++++++++++++++
#COMP 左>右，值-1；左等于右，值0；左<右，值1
port_line=$(cat $yaml_tmp | grep -n "^port:" | awk -F ":" '{print $1}' | head -1)
echo_date "port:行数为$port_line" >> $LOG_FILE
echo_date "proxies:行数为$proxies_line" >> $LOG_FILE

COMP=$(versioncmp $proxies_line $port_line)
if [ "$COMP" == "-1" ];then
    echo_date "proxies行数大于port行数，说明port在proxies之前，截取proxies到末尾内容" >> $LOG_FILE
    tail +$proxies_line $yaml_tmp > /tmp/a.yaml
elif [ "$COMP" == "1" ];then
    echo_date "proxies行数小于port行数，说明port在proxies之后，截取proxies到port行-1之间内容" >> $LOG_FILE
    b=$(($port_line-1))
    sed -n "$proxies_line,$b p" $yaml_tmp > /tmp/a.yaml
fi
#20200902---------------
cat /tmp/a.yaml > $yaml_tmp

#插入一行免得出错
sed -i '$a' $yaml_tmp
cat $head_tmp >> $yaml_tmp
echo_date "标准头文件合并完毕" >> $LOG_FILE
sed -i "s/192.168.2.1:9990/$lan_ip:9990/g" $yaml_tmp
echo_date "恢复上传配置mode模式" >> $LOG_FILE
[ -n "$mode" ] && sed -i "s/mode: rule/mode: $mode/g" $yaml_tmp
#删除PROCESS-NAME规则，因为路由用不上
sed -i '/PROCESS-NAME/d' $yaml_tmp

echo_date "移动yaml文件到/koolshare/merlinclash/yaml_bak/ 以" >> $LOG_FILE
echo_date "及/koolshare/merlinclash/yaml_use/目录下" >> $LOG_FILE
mv -f $yaml_tmp /koolshare/merlinclash/yaml_bak/$name
cp -rf /koolshare/merlinclash/yaml_bak/$name /koolshare/merlinclash/yaml_use/$name
#删除/upload可能残留的yaml格式文件
rm -rf /tmp/upload/*.yaml
rm -rf /tmp/a.yaml
#生成新的txt文件

rm -rf $fp/yamls.txt
echo_date "创建yaml文件列表" >> $LOG_FILE
#find $fp  -name "*.yaml" |sed 's#.*/##' >> $fp/yamls.txt
find $fp  -name "*.yaml" |sed 's#.*/##' |sed '/^$/d' | awk -F'.' '{print $1}' >> $fp/yamls.txt
#创建软链接
ln -sf /koolshare/merlinclash/yaml_bak/yamls.txt /tmp/upload/yamls.txt
#
echo_date "配置文件【处理完成】，如下拉框没找到配置文件，请手动刷新页面" >>"$LOG_FILE"

