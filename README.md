# meilin
梅林软路由器相关操作
## 1.配置路由，准备文件

### 1.1配置路由

控制面板中

【外部网络】-> 设置WAN 联机类型为 动态IP

【无线网络】->设置无线网基础配置

【系统管理】->【系统设置】开启ssh ->Enable JFFS custom scripts and configs打开  ->在本地终端连接路由器 

```shell
ssh admin@路由器ip
```

### 1.2下载clash

开启路由器的SSH功能，登录并输入以下命令后，再进行插件的离线安装

```shell
sed -i 's/\tdetect_package/\t# detect_package/g' /koolshare/scripts/ks_tar_install.sh
```

打开jffs后就可以在软件中心安装插件了。因为本机系统为koolshare 改版梅林系统，去clash的[git](https://github.com/Dreamacro/clash/releases)上下载相应的版本上传到梅林系统中会报错，所以安装了改版的clash ->meilin clash（也要下载和cpu和固件版本相对应的安装包）

### 1.3导入clash配置文件clash.ymal

clash是通过加载配置文件工作的。所以，现在只需要在已安装的clash中导入我们自己的配置文件就，就可以工作了。关于clash的配置参考https://github.com/Dreamacro/clash/wiki/configuration