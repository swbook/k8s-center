# containerd1.6.20+kubernetes1.26.4+CentOS8.5.2111集群二进制部署

**说明：**

- 采用最新稳定版本，容器运行时采用`containerd`，以二进制部署方式安装并完成验证。
- 梳理以往部署步骤及规划，更加明确、清晰、简洁、高效。主要操作依次为：【1】`containerd`容器运行时；【2】制作证书；【3】`etcd`集群；【4】高可用方案；【5】核心组件（`kube-apiserver`、`kubectrl`、`kube-controller-manager`、`kube-schedule`、`kubelet`、`kube-proxy`）;【6】核心插件（`calico`、`coredns`、`metrics-server`、`dashboard`）。
- 集群内`dns`解析/服务发现验证，`pod`跨节点跨命名空间访问验证。
- 部署过程中的问题借助了`chatGPT`、搜索引擎。

- 二零二叁五一于广州。

-------------------------------

## 一、软件及资源获得

==本实验全部软件及资源均为开源，由github、阿里云、华为云、及相关软件官方提供，并在文档中注明来源。==

### 01 下载CentOS-8.5.2111-x86_64-boot.iso

阿里云开源镜像站：

> https://mirrors.aliyun.com/centos/8.5.2111/isos/x86_64/CentOS-8.5.2111-x86_64-boot.iso?spm=a2c6h.25603864.0.0.3ada53bacX0rre

### 02 下载k8s-v1.26.4

github：

> https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.26.md#server-binaries

> https://dl.k8s.io/v1.26.4/kubernetes-server-linux-amd64.tar.gz

### 03 下载etcd-v3.5.8

github：

> https://github.com/etcd-io/etcd/
>
> https://github.com/etcd-io/etcd/releases/download/v3.5.8/etcd-v3.5.8-linux-amd64.tar.gz

华为云：https://repo.huaweicloud.com/etcd/

### 04 下载containerd-v1.6.20

github：https://github.com/containerd/containerd/releases/tag/v1.6.20

> https://github.com/containerd/containerd/releases/download/v1.6.20/cri-containerd-cni-1.6.20-linux-amd64.tar.gz
>
> https://github.com/opencontainers/runc/releases/download/v1.1.7/libseccomp-2.5.4.tar.gz
>
> https://github.com/opencontainers/runc/releases/download/v1.1.7/runc.amd64

### 05 下载crictl-v1.24.2

github：https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.24.2/crictl-v1.24.2-linux-amd64.tar.gz

### 06 下载calico-v3.25.1

- `release-v3.25.1.tgz`: container images, binaries, and kubernetes manifests.

github：https://github.com/projectcalico/calico/releases

> https://github.com/projectcalico/calico/releases/download/v3.25.1/calicoctl-linux-amd64

### 07 下载cfssl-v1.6.4

github：https://github.com/cloudflare/cfssl/releases

> https://github.com/cloudflare/cfssl/releases/download/v1.6.4/cfssl_1.6.4_linux_amd64
>
> https://github.com/cloudflare/cfssl/releases/download/v1.6.4/cfssljson_1.6.4_linux_amd64

### 08 下载nginx-1.24.0

http://nginx.org：http://nginx.org/download/nginx-1.24.0.tar.gz  （Stable version）

### 09 资源清单与镜像

| 类型 | 名称                               | 下载链接                                                     | 说明 |
| ---- | ---------------------------------- | ------------------------------------------------------------ | ---- |
| 资源 | calico.yaml                        | https://docs.tigera.io/archive/v3.25/manifests/calico.yaml   | 部署 |
| 资源 | coredns.yaml.base                  | https://github.com/kubernetes/kubernetes/blob/v1.26.4/cluster/addons/dns/coredns/coredns.yaml.base | 部署 |
| 资源 | recommended.yaml                   | https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml | 部署 |
| 资源 | components.yaml （metrics server） | https://mirrors.chenby.cn/https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/high-availability.yaml | 部署 |
| 镜像 | metrics-server:v0.6.3              | registry.aliyuncs.com/google_containers/metrics-server:v0.6.3 | 部署 |
| 镜像 | coredns:1.8.6                      | registry.aliyuncs.com/google_containers/coredns:1.8.6        | 部署 |
| 镜像 | coredns:v1.10.0                    | registry.aliyuncs.com/google_containers/coredns:v1.10.0      | 部署 |
| 镜像 | dashboard:v2.7.0                   | kubernetesui/dashboard:v2.7.0                                | 部署 |
| 镜像 | metrics-scraper:v1.0.8             | kubernetesui/metrics-scraper:v1.0.8                          | 部署 |
| 镜像 | pause:3.6                          | registry.aliyuncs.com/google_containers/pause:3.6            | 部署 |
| 镜像 | cni:v3.25.0                        | docker.io/calico/cni:v3.25.0                                 | 部署 |
| 镜像 | node:v3.25.0                       | docker.io/calico/node:v3.25.0                                | 部署 |
| 镜像 | kube-controllers:v3.25.0           | docker.io/calico/kube-controllers:v3.25.0                    | 部署 |

## 二、创建虚拟机CentOS8.5-tmp

### 01 安装源

将安装源(软件源)配置为阿里的：

- 协议选择为：`http://`
  路径是：`mirrors.aliyun.com/centos/8.5.2111/BaseOS/x86_64/os/`
  URL类型是：`软件库URL`
  注意上面的阿里路径最后要记得加上一个斜杠==/==

![image-20230426171006565](k8s-v1.26.4 + CentOS-8.5.2111集群部署.assets/image-20230426171006565.png)

### 02 软件选择：最小安装

![image-20230426171323016](k8s-v1.26.4 + CentOS-8.5.2111集群部署.assets/image-20230426171323016.png)

安装完成，重启系统

```
# cat /etc/redhat-release

# uname -r
```

![image-20230426173507247](k8s-v1.26.4 + CentOS-8.5.2111集群部署.assets/image-20230426173507247.png)

### 03 基本设置

```ini
##1 删除ssh的key文件：/etc/ssh/ssh_host_*
rm -rf  /etc/ssh/ssh_host_*
##2 清空/etc/machine-id
cat /dev/null > /etc/machine-id
##3 查看/etc/sysconfig/network-scripts目录下是否有ifcfg-ens*文件
ls /etc/sysconfig/network-scripts
vi /etc/sysconfig/network-scripts/ifcfg-ens160  ## 只需要保留以下信息
TYPE=Ethernet
BOOTPROTO=dhcp
NAME=ens160
DEVICE=ens160
ONBOOT=yes
```

### 04 编写set.sh设置IP、hostname

```ini
#!/bin/bash
if [ $# -eq 0 ]; then
	echo "usage: `basename $0` num"
	exit 1
fi
[[ $1 =~ ^[0-9]+$ ]]
if [ $? -ne 0 ]; then
	echo "usage: `basename $0` 10~240"
	exit 1
fi

cat > /etc/sysconfig/network-scripts/ifcfg-ens160 <<EOF
TYPE=Ethernet
BOOTPROTO=none
NAME=ens160
DEVICE=ens160
ONBOOT=yes
IPADDR=192.168.26.${1}
NETMASK=255.255.255.0
GATEWAY=192.168.26.2
DNS1=192.168.26.2
EOF

nmcli connection reload
nmcli connection up ens160 &> /dev/null

ip=$(ifconfig ens160 | awk '/inet /{print $2}')
sed -i '/192/d' /etc/issue
echo $ip
echo $ip >> /etc/issue
hostnamectl set-hostname vm${1}.centos85
echo "192.168.26.$1 vm${1}.centos85 vm${1}" >> /etc/hosts
```

==与/etc/sysconfig/network-scripts/ifcfg-ens160一致，ens32改为ens160==

==centos8与centos7重启网络命令不同==

```
##centos7重启网络
systemctl restart network &> /dev/null
##centos8重启网络
nmcli connection reload
nmcli connection up ens160 &> /dev/null
```

==因为最小化安装，可能缺少ifconfig，需要：yum install net-tools -y==

```ini
##配置yum源
sed -e 's|^mirrorlist=|#mirrorlist=|g' -e 's|^#baseurl=http://mirror.centos.org/$contentdir|baseurl=https://mirrors.aliyun.com/centos|g' -i.bak /etc/yum.repos.d/CentOS-*.repocat  
##安装
yum update -y
yum install net-tools -y
```

==poweroff 关掉模板机，以后不要启动，否则需要重新设置。==



## 三、主机准备

| 序号 | 主机名 | IP            | OS                            | 内核                        | 运行时           | K8S              | 工具包   |
| ---- | ------ | ------------- | ----------------------------- | --------------------------- | ---------------- | ---------------- | -------- |
| 1    | vm61   | 192.168.26.61 | CentOS Linux release 8.5.2111 | 4.18.0-348.7.1.el8_5.x86_64 | containerd1.6.20 | kubernetes1.26.4 |          |
| 2    | vm62   | 192.168.26.62 | CentOS Linux release 8.5.2111 | 4.18.0-348.7.1.el8_5.x86_64 | containerd1.6.20 | kubernetes1.26.4 | 开发工具 |
| 3    | vm63   | 192.168.26.63 | CentOS Linux release 8.5.2111 | 4.18.0-348.7.1.el8_5.x86_64 | containerd1.6.20 | kubernetes1.26.4 |          |

### 01 主机名与hosts本地解析

```sh
root@vm61 ~]# hostnamectl set-hostname vm61
root@vm62 ~]# hostnamectl set-hostname vm62
root@vm63 ~]# hostnamectl set-hostname vm63
~]# cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.26.61 vm61.centos85 vm61
192.168.26.62 vm62.centos85 vm62
192.168.26.63 vm63.centos85 vm63
```

### 02 关闭防火墙

```sh
~]# systemctl disable --now firewalld
Removed /etc/systemd/system/multi-user.target.wants/firewalld.service.
Removed /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
~]# firewall-cmd --state
not running
```

### 03 关闭SELINUX

```sh
~]# sed -i 's#SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config
~]# reboot
~]# sestatus
SELinux status:                 disabled
```

==修改SELinux配置需要重启操作系统。==

### 04 关闭交换分区

```sh
~]# sed -ri 's/.*swap.*/#&/' /etc/fstab
~]# swapoff -a && sysctl -w vm.swappiness=0
~]# cat /etc/fstab
#UUID=5d57931a-9c6b-45d9-aa18-c545af28117d none                    swap    defaults        0 0
~]# free -m
              total        used        free      shared  buff/cache   available
Mem:           3709         188        3321          16         199        3296
Swap:             0           0           0
```

### 05 配置ulimit

```sh
~]# ulimit -SHn 65535
~]# cat <<EOF >> /etc/security/limits.conf
* soft nofile 655360
* hard nofile 131072
* soft nproc 655350
* hard nproc 655350
* soft memlock unlimited
* hard memlock unlimited
EOF
```

### 06 网络配置

```sh
~]# cat > /etc/NetworkManager/conf.d/calico.conf << EOF 
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:tunl*
EOF
~]# systemctl restart NetworkManager
```

### 07 ipvs管理工具安装及模块加载

```sh
~]# yum install ipvsadm ipset sysstat conntrack libseccomp -y

~]# cat >> /etc/modules-load.d/ipvs.conf <<EOF 
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
ip_tables
ip_set
xt_set
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
EOF

~]# systemctl restart systemd-modules-load.service

~]# lsmod | grep -e ip_vs -e nf_conntrack
ip_vs_sh               16384  0
ip_vs_wrr              16384  0
ip_vs_rr               16384  0
ip_vs                 172032  6 ip_vs_rr,ip_vs_sh,ip_vs_wrr
nf_conntrack          172032  1 ip_vs
nf_defrag_ipv6         20480  2 nf_conntrack,ip_vs
nf_defrag_ipv4         16384  1 nf_conntrack
libcrc32c              16384  3 nf_conntrack,xfs,ip_vs
```

### 08 加载containerd相关内核模块

```sh
临时加载模块
~]# modprobe overlay
~]# modprobe br_netfilter

永久性加载模块
~]# cat > /etc/modules-load.d/containerd.conf << EOF
overlay
br_netfilter
EOF

设置为开机启动
~]# systemctl restart systemd-modules-load.service ##systemctl enable --now systemd-modules-load.service
```

### 09 开启内核路由转发及网桥过滤

```sh
~]# cat <<EOF > /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.may_detach_mounts = 1
vm.overcommit_memory=1
vm.panic_on_oom=0
fs.inotify.max_user_watches=89100
fs.file-max=52706963
fs.nr_open=52706963
net.netfilter.nf_conntrack_max=2310720

net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl =15
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 327680
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_conntrack_max = 131072
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 0
net.core.somaxconn = 16384
EOF

~]# sysctl --system
所有节点配置完内核后，重启服务器，保证重启后内核依旧加载
~]# reboot -h now

重启后查看ipvs模块加载情况：
~]# lsmod | grep --color=auto -e ip_vs -e nf_conntrack

重启后查看containerd相关模块加载情况：
~]# lsmod | egrep 'br_netfilter | overlay'
```

### 10 时间同步

略

### 11 设置rpm包下载保存

==yum安装时rpm包默认不保存，如果需要保存则设置`keepcache=1`，保存位置默认`/var/cache/dnf/*/packages`==

```sh
~]# cat /etc/dnf/dnf.conf
[main]
keepcache=1
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=True
best=True
skip_if_unavailable=False

 ~]# ls -l /var/cache/dnf/*/packages |grep '.rpm' |wc -l
```

### 12 安装开发工具

==因为最小化安装，没有安装开发工具，导致一些需要编译安装的软件包不能正常安装。==

```sh
 ~]# yum grouplist
可用环境组：
   带 GUI 的服务器
   服务器
   工作站
   虚拟化主机
   定制操作系统
已安装的环境组：
   最小安装
可用组：
   容器管理
   .NET 核心开发
   RPM 开发工具
   开发工具
   图形管理工具
   无头系统管理
   传统 UNIX 兼容性
   网络服务器
   科学记数法支持
   安全性工具
   智能卡支持
   系统工具
 ~]# yum -y groupinstall "Development Tools" #如果是中文，使用"开发*"
```

## 四、部署规划

### 01 软件部署目录

```sh
]# mkdir -p /opt/{app,cfg,cert,bin}
## /opt/app 存放部署源文件
## /opt/cfg 存放配置文件
## /opt/cert 存放证书
## /opt/bin 链接/opt/app下的源文件，去除文件名中的版本号，方便升级时只需要更改链接即可。
```

### 02 集群网络规划

| 网络名称    | 网段            | 备注                                                         |
| ----------- | --------------- | ------------------------------------------------------------ |
| Node网络    | 192.168.26.0/24 | **Node IP**，Node节点的IP地址，即物理机（宿主机）的网卡地址。 |
| Service网络 | 10.96.0.0/16    | **Cluster IP**，也可叫**Service IP**，Service的IP地址。`service-cluster-ip-range`定义Service IP地址范围的参数。 |
| Pod网络     | 10.244.0.0/16   | **Pod IP**，Pod的IP地址，docker0网桥分配的地址。`cluster-cidr`定义Pod网络CIDR地址范围的参数。 |

配置：

```ini
apiserver：
--service-cluster-ip-range 10.96.0.0/16    ##Service网络 10.96.0.0/16

controller：
--cluster-cidr 10.244.0.0/16   ##Pod网络 10.244.0.0/16
--service-cluster-ip-range 10.96.0.0/16   ##ervice网络 10.96.0.0/16

kubelet：
--cluster-dns 10.96.0.2   ## 解析Service，10.96.0.2

proxy：
--cluster-cidr 10.244.0.0/16   ##Pod网络 10.244.0.0/16
```

### 03 证书生成工具

```sh
[root@vm61 app]# mv cfssl_1.6.4_linux_amd64 /usr/local/bin/cfssl
[root@vm61 app]# mv cfssljson_1.6.4_linux_amd64 /usr/local/bin/cfssljson
[root@vm61 app]# chmod +x cfssl*
[root@vm61 app]# cfssl version
Version: 1.6.4
Runtime: go1.18
```



## 五、容器运行时准备

containerd：自身带的runc依赖libseccomp2.3.1，不能集群初始化，需要`yum -y install libseccomp-devel`

软件版本：containerd 1.7.0 + runc 1.1.7 + libseccomp2.5.4

```ini
-rw-r--r-- 1 root root 146373924 5月   2 09:19 cri-containerd-cni-1.7.0-linux-amd64.tar.gz
-rw-r--r-- 1 root root    637228 5月   2 09:19 libseccomp-2.5.4.tar.gz
-rw-r--r-- 1 root root   9644288 5月   2 09:19 runc.amd64
```

### 01 安装containerd

```sh
]# tar xf cri-containerd-cni-1.6.20-linux-amd64.tar.gz  -C /
## 创建配置文件
]# mkdir /etc/containerd
]# containerd config default > /etc/containerd/config.toml
]# vi /etc/containerd/config.toml ## 修改以下两项
sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.6"
systemd_cgroup = true
```

```ini
# cat >/etc/containerd/config.toml<<EOF
root = "/var/lib/containerd"
state = "/run/containerd"
oom_score = -999

[grpc]
  address = "/run/containerd/containerd.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

[debug]
  address = ""
  uid = 0
  gid = 0
  level = ""

[metrics]
  address = ""
  grpc_histogram = false

[cgroup]
  path = ""

[plugins]
  [plugins.cgroups]
    no_prometheus = false
  [plugins.cri]
    stream_server_address = "127.0.0.1"
    stream_server_port = "0"
    enable_selinux = false
    sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.6"
    stats_collect_period = 10
    systemd_cgroup = true
    enable_tls_streaming = false
    max_container_log_line_size = 16384
    [plugins.cri.containerd]
      snapshotter = "overlayfs"
      no_pivot = false
      [plugins.cri.containerd.default_runtime]
        runtime_type = "io.containerd.runtime.v1.linux"
        runtime_engine = ""
        runtime_root = ""
      [plugins.cri.containerd.untrusted_workload_runtime]
        runtime_type = ""
        runtime_engine = ""
        runtime_root = ""
    [plugins.cri.cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"
      conf_template = "/etc/cni/net.d/10-default.conf"
    [plugins.cri.registry]
      [plugins.cri.registry.mirrors]
        [plugins.cri.registry.mirrors."docker.io"]
          endpoint = [
            "https://docker.mirrors.ustc.edu.cn",
            "http://hub-mirror.c.163.com"
          ]
        [plugins.cri.registry.mirrors."gcr.io"]
          endpoint = [
            "https://gcr.mirrors.ustc.edu.cn"
          ]
        [plugins.cri.registry.mirrors."k8s.gcr.io"]
          endpoint = [
            "https://gcr.mirrors.ustc.edu.cn/google-containers/"
          ]
        [plugins.cri.registry.mirrors."quay.io"]
          endpoint = [
            "https://quay.mirrors.ustc.edu.cn"
          ]
        [plugins.cri.registry.mirrors."harbor.kubemsb.com"]
          endpoint = [
            "http://harbor.kubemsb.com"
          ]
    [plugins.cri.x509_key_pair_streaming]
      tls_cert_file = ""
      tls_key_file = ""
  [plugins.diff-service]
    default = ["walking"]
  [plugins.linux]
    shim = "containerd-shim"
    runtime = "runc"
    runtime_root = ""
    no_shim = false
    shim_debug = false
  [plugins.opt]
    path = "/opt/containerd"
  [plugins.restart]
    interval = "10s"
  [plugins.scheduler]
    pause_threshold = 0.02
    deletion_threshold = 0
    mutation_threshold = 100
    schedule_delay = "0s"
    startup_delay = "100ms"
EOF
```

### 02 安装libseccomp2.5.4

==此步在runc运行出错时执行。==

```sh
]# tar xf libseccomp-2.5.4.tar.gz
]# cd libseccomp-2.5.4
libseccomp-2.5.4]#  yum install gperf -y  ## 安装依赖
上次元数据过期检查：1:07:47 前，执行于 2023年05月02日 星期二 08时42分20秒。
未找到匹配的参数: gperf
错误：没有任何匹配: gperf
libseccomp-2.5.4]# yum install epel-release ## 如果再报错，执行下面的epel安装源
libseccomp-2.5.4]# yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
libseccomp-2.5.4]# yum install gperf -y
libseccomp-2.5.4]# ./configure
libseccomp-2.5.4]# make && make install
libseccomp-2.5.4]# find / -name "libseccomp.so"
/usr/local/lib/libseccomp.so
/opt/app/libseccomp-2.5.4/src/.libs/libseccomp.so
libseccomp-2.5.4]# ll /usr/local/lib/libsec*
-rw-r--r-- 1 root root 1068536 5月   2 10:19 /usr/local/lib/libseccomp.a
-rwxr-xr-x 1 root root     937 5月   2 10:19 /usr/local/lib/libseccomp.la
lrwxrwxrwx 1 root root      19 5月   2 10:19 /usr/local/lib/libseccomp.so -> libseccomp.so.2.5.4
lrwxrwxrwx 1 root root      19 5月   2 10:19 /usr/local/lib/libseccomp.so.2 -> libseccomp.so.2.5.4
-rwxr-xr-x 1 root root  569040 5月   2 10:19 /usr/local/lib/libseccomp.so.2.5.4
```

### 03 安装runc

```sh
app]# chmod +x runc.amd64
## 查找containerd安装时已安装的runc所在的位置，然后替换
app]# which runc
/usr/local/sbin/runc
app]# mv runc.amd64 /usr/local/sbin/runc
app]# runc  ## 执行runc命令，如果有命令帮助则为正常
...
VERSION:
   1.1.7
commit: v1.1.7-0-g860f061b
spec: 1.0.2-dev
go: go1.20.3
libseccomp: 2.5.4
...
```

### 04 启动检查

```sh
## 启动
]# systemctl enable --now containerd
]# containerd --version
containerd github.com/containerd/containerd v1.6.20 2806fc1057397dbaeefbea0e4e17bddfbd388f38
]# ctr version
Client:
  Version:  v1.6.20
  Revision: 2806fc1057397dbaeefbea0e4e17bddfbd388f38
  Go version: go1.19.7

Server:
  Version:  v1.6.20
  Revision: 2806fc1057397dbaeefbea0e4e17bddfbd388f38
  UUID: f06a02e0-e338-4f00-a295-e370a05d3358
```



### 05 配置crictl客户端连接的运行时位置[没用]

```sh
## 下载
# wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.24.2/crictl-v1.24.2-linux-amd64.tar.gz
## 解压
app]# tar xf crictl-v1.24.2-linux-amd64.tar.gz -C /usr/bin/
## 生成配置文件
cat > /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
EOF

## 测试
]# systemctl restart  containerd
]# crictl info  ## 能正常如下输出表示成功
...
    "containerdRootDir": "/var/lib/containerd",
    "containerdEndpoint": "/run/containerd/containerd.sock",
    "rootDir": "/var/lib/containerd/io.containerd.grpc.v1.cri",
    "stateDir": "/run/containerd/io.containerd.grpc.v1.cri"
  },
  "golang": "go1.19.7",
  "lastCNILoadStatus": "OK",
  "lastCNILoadStatus.default": "OK"
}
```

### 05 在其它节点安装

==在vm61、vm63上安装，这里给出vm61上的操作。==

```sh
##01 containerd: 复制软件、配置文件，重复上面步骤
vm61 app]# scp root@vm62:/opt/app/cri-containerd-cni-1.6.20-linux-amd64.tar.gz /opt/app/.
vm61 app]# tar xf cri-containerd-cni-1.7.0-linux-amd64.tar.gz  -C /
vm61 app]# mkdir /etc/containerd
vm61 app]# scp root@vm62:/etc/containerd/config.toml /etc/containerd/.
vm61 app]# systemctl enable --now containerd
vm61 app]# systemctl status containerd
vm61 app]# containerd --version
vm61 app]# ctr version
vm61 app]# runc  ## 不更新runc，忽略02、03步
...
VERSION:
   1.1.7
commit: v1.1.7-0-g860f061b
spec: 1.0.2-dev
go: go1.20.3
libseccomp: 2.5.4
...
```

## 六、创建证书

### 01 创建CA根证书

- ca-csr.json

  ```json
  cat > ca-csr.json   << EOF 
  {
    "CN": "kubernetes",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "Kubernetes",
        "OU": "Kubernetes-manual"
      }
    ],
    "ca": {
      "expiry": "876000h"
    }
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert -initca ca-csr.json | cfssljson -bare ca
vm61 cert]# ls -l ca*pem
-rw------- 1 root root 1675 5月   2 17:11 ca-key.pem
-rw-r--r-- 1 root root 1363 5月   2 17:11 ca.pem
```

- ca-config.json

  ```json
  cat > ca-config.json << EOF 
  {
    "signing": {
      "default": {
        "expiry": "876000h"
      },
      "profiles": {
        "kubernetes": {
          "usages": [
              "signing",
              "key encipherment",
              "server auth",
              "client auth"
          ],
          "expiry": "876000h"
        }
      }
    }
  }
  EOF
  ```

### 02 创建etcd证书

- etcd-ca-csr.json

  ```json
  cat > etcd-ca-csr.json  << EOF 
  {
    "CN": "etcd",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "etcd",
        "OU": "Etcd Security"
      }
    ],
    "ca": {
      "expiry": "876000h"
    }
  }
  EOF
  ```

- etcd-csr.json

  ```json
  cat > etcd-csr.json << EOF 
  {
    "CN": "etcd",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "etcd",
        "OU": "Etcd Security"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert -initca etcd-ca-csr.json | cfssljson -bare etcd-ca
vm61 cert]# ls -l etcd-ca*pem
-rw------- 1 root root 1679 5月   2 17:18 etcd-ca-key.pem
-rw-r--r-- 1 root root 1318 5月   2 17:18 etcd-ca.pem

vm61 cert]# cfssl gencert \
   -ca=./etcd-ca.pem \
   -ca-key=./etcd-ca-key.pem \
   -config=./ca-config.json \
   -hostname=127.0.0.1,vm61,vm62,vm63,192.168.26.61,192.168.26.62,192.168.26.63 \
   -profile=kubernetes \
   etcd-csr.json | cfssljson -bare ./etcd
vm61 cert]# ls -l etcd*pem
-rw------- 1 root root 1679 5月   2 17:18 etcd-ca-key.pem
-rw-r--r-- 1 root root 1318 5月   2 17:18 etcd-ca.pem
-rw------- 1 root root 1675 5月   2 17:24 etcd-key.pem
-rw-r--r-- 1 root root 1432 5月   2 17:24 etcd.pem
```

### 03 创建kube-apiserver证书

- apiserver-csr.json

  ```json
  cat > apiserver-csr.json << EOF 
  {
    "CN": "kube-apiserver",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "Kubernetes",
        "OU": "Kubernetes-manual"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert   \
-ca=./ca.pem   \
-ca-key=./ca-key.pem   \
-config=./ca-config.json   \
-hostname=127.0.0.1,192.168.26.61,192.168.26.62,192.168.26.63,10.96.0.1,kubernetes,kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster,kubernetes.default.svc.cluster.local  \
-profile=kubernetes   apiserver-csr.json | cfssljson -bare ./apiserver
vm61 cert]# ls -l apiserver*pem
-rw------- 1 root root 1675 5月   2 17:38 apiserver-key.pem
-rw-r--r-- 1 root root 1684 5月   2 17:38 apiserver.pem
```

- front-proxy-ca-csr.json

  ```json
  cat > front-proxy-ca-csr.json  << EOF 
  {
    "CN": "kubernetes",
    "key": {
       "algo": "rsa",
       "size": 2048
    },
    "ca": {
      "expiry": "876000h"
    }
  }
  EOF
  ```

- front-proxy-client-csr.json

  ```json
  cat > front-proxy-client-csr.json  << EOF 
  {
    "CN": "front-proxy-client",
    "key": {
       "algo": "rsa",
       "size": 2048
    }
  }
  EOF
  ```

```sh
## 生成kube-apiserver聚合证书
vm61 cert]# cfssl gencert -initca front-proxy-ca-csr.json | cfssljson -bare ./front-proxy-ca
vm61 cert]# ls -l front-proxy-ca*pem
-rw------- 1 root root 1675 5月   2 17:41 front-proxy-ca-key.pem
-rw-r--r-- 1 root root 1094 5月   2 17:41 front-proxy-ca.pem
vm61 cert]# cfssl gencert  \
-ca=./front-proxy-ca.pem   \
-ca-key=./front-proxy-ca-key.pem   \
-config=./ca-config.json   \
-profile=kubernetes front-proxy-client-csr.json | cfssljson -bare ./front-proxy-client
vm61 cert]# ls -l front-proxy-client*pem
-rw------- 1 root root 1675 5月   2 17:43 front-proxy-client-key.pem
-rw-r--r-- 1 root root 1188 5月   2 17:43 front-proxy-client.pem
```

### 04 创建kube-controller-manager的证书

- manager-csr.json，用于生成配置文件controller-manager.kubeconfig

  ```json
  cat > manager-csr.json << EOF 
  {
    "CN": "system:kube-controller-manager",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "system:kube-controller-manager",
        "OU": "Kubernetes-manual"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert \
   -ca=./ca.pem \
   -ca-key=./ca-key.pem \
   -config=./ca-config.json \
   -profile=kubernetes \
   manager-csr.json | cfssljson -bare ./controller-manager
vm61 cert]# ls -l controller-manager*pem
-rw------- 1 root root 1679 5月   2 17:46 controller-manager-key.pem
-rw-r--r-- 1 root root 1501 5月   2 17:46 controller-manager.pem
```

- admin-csr.json，用于生成配置文件admin.kubeconfig

  ```json
  cat > admin-csr.json << EOF 
  {
    "CN": "admin",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "system:masters",
        "OU": "Kubernetes-manual"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert \
   -ca=./ca.pem \
   -ca-key=./ca-key.pem \
   -config=./ca-config.json \
   -profile=kubernetes \
   admin-csr.json | cfssljson -bare ./admin
vm61 cert]# ls -l admin*pem
-rw------- 1 root root 1679 5月   2 17:49 admin-key.pem
-rw-r--r-- 1 root root 1444 5月   2 17:49 admin.pem
```

### 05 创建kube-schedule证书

- scheduler-csr.json，用于生成配置文件scheduler.kubeconfig

  ```json
  cat > scheduler-csr.json << EOF 
  {
    "CN": "system:kube-scheduler",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "system:kube-scheduler",
        "OU": "Kubernetes-manual"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert \
   -ca=./ca.pem \
   -ca-key=./ca-key.pem \
   -config=./ca-config.json \
   -profile=kubernetes \
   scheduler-csr.json | cfssljson -bare ./scheduler
vm61 cert]# ls -l scheduler*pem
-rw------- 1 root root 1679 5月   2 17:55 scheduler-key.pem
-rw-r--r-- 1 root root 1476 5月   2 17:55 scheduler.pem
```

### 06 创建kube-prox证书

- kube-proxy-csr.json，用于生成配置文件kube-proxy.kubeconfig

  ```json
  cat > kube-proxy-csr.json  << EOF 
  {
    "CN": "system:kube-proxy",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "Beijing",
        "L": "Beijing",
        "O": "system:kube-proxy",
        "OU": "Kubernetes-manual"
      }
    ]
  }
  EOF
  ```

```sh
vm61 cert]# cfssl gencert \
   -ca=./ca.pem \
   -ca-key=./ca-key.pem \
   -config=./ca-config.json \
   -profile=kubernetes \
   kube-proxy-csr.json | cfssljson -bare ./kube-proxy
vm61 cert]# ls -l kube-proxy*pem
-rw------- 1 root root 1679 5月   2 17:57 kube-proxy-key.pem
-rw-r--r-- 1 root root 1464 5月   2 17:57 kube-proxy.pem
```

### 07 创建ServiceAccount Key - secret

```sh
]# openssl genrsa -out /opt/cert/sa.key 2048
]# openssl rsa -in /opt/cert/sa.key -pubout -out /opt/cert/sa.pub
]# ls -l /opt/cert/sa*
-rw------- 1 root root 1679 5月   2 20:13 /opt/cert/sa.key
-rw-r--r-- 1 root root  451 5月   2 20:14 /opt/cert/sa.pub
```

### 08 分发证书到各节点

```sh
]# scp -r /opt/cert root@vm62:/opt/.
]# scp -r /opt/cert root@vm63:/opt/.
```

## 七、etcd集群部署

```sh
## 解压软件包，并将运行软件放到/opt/bin目录
vm61 app]# tar -xf etcd-v3.5.8-linux-amd64.tar.gz -C /opt/bin
]# ls -l /opt/bin/etcd*
-rwxr-xr-x 1 528287 89939 22470656 4月  13 18:11 /opt/bin/etcd
-rwxr-xr-x 1 528287 89939 16998400 4月  13 18:11 /opt/bin/etcdctl
]# ln -s /opt/bin/etcdctl /usr/local/bin/etcdctl
]# etcdctl version
etcdctl version: 3.5.8
API version: 3.5

## 复制软件到其他节点vm62、vm63
]# scp -r /opt/bin/ root@vm62:/opt/
]# scp -r /opt/bin/ root@vm63:/opt/
]# ln -s /opt/bin/etcdctl /usr/local/bin/etcdctl
```

### 01 配置文件

- vm61：/opt/cfg/etcd.config.yml

```yaml
cat > /opt/cfg/etcd.config.yml << EOF 
name: 'vm61'
data-dir: /var/lib/etcd
wal-dir: /var/lib/etcd/wal
snapshot-count: 5000
heartbeat-interval: 100
election-timeout: 1000
quota-backend-bytes: 0
listen-peer-urls: 'https://192.168.26.61:2380'
listen-client-urls: 'https://192.168.26.61:2379,http://127.0.0.1:2379'
max-snapshots: 3
max-wals: 5
cors:
initial-advertise-peer-urls: 'https://192.168.26.61:2380'
advertise-client-urls: 'https://192.168.26.61:2379'
discovery:
discovery-fallback: 'proxy'
discovery-proxy:
discovery-srv:
initial-cluster: 'vm61=https://192.168.26.61:2380,vm62=https://192.168.26.62:2380,vm63=https://192.168.26.63:2380'
initial-cluster-token: 'etcd-k8s-cluster'
initial-cluster-state: 'new'
strict-reconfig-check: false
enable-v2: true
enable-pprof: true
proxy: 'off'
proxy-failure-wait: 5000
proxy-refresh-interval: 30000
proxy-dial-timeout: 1000
proxy-write-timeout: 5000
proxy-read-timeout: 0
client-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
peer-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  peer-client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
debug: false
log-package-levels:
log-outputs: [default]
force-new-cluster: false
EOF
```

- vm62：/opt/cfg/etcd.config.yml

```yml
cat > /opt/cfg/etcd.config.yml << EOF 
name: 'vm62'
data-dir: /var/lib/etcd
wal-dir: /var/lib/etcd/wal
snapshot-count: 5000
heartbeat-interval: 100
election-timeout: 1000
quota-backend-bytes: 0
listen-peer-urls: 'https://192.168.26.62:2380'
listen-client-urls: 'https://192.168.26.62:2379,http://127.0.0.1:2379'
max-snapshots: 3
max-wals: 5
cors:
initial-advertise-peer-urls: 'https://192.168.26.62:2380'
advertise-client-urls: 'https://192.168.26.62:2379'
discovery:
discovery-fallback: 'proxy'
discovery-proxy:
discovery-srv:
initial-cluster: 'vm61=https://192.168.26.61:2380,vm62=https://192.168.26.62:2380,vm63=https://192.168.26.63:2380'
initial-cluster-token: 'etcd-k8s-cluster'
initial-cluster-state: 'new'
strict-reconfig-check: false
enable-v2: true
enable-pprof: true
proxy: 'off'
proxy-failure-wait: 5000
proxy-refresh-interval: 30000
proxy-dial-timeout: 1000
proxy-write-timeout: 5000
proxy-read-timeout: 0
client-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
peer-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  peer-client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
debug: false
log-package-levels:
log-outputs: [default]
force-new-cluster: false
EOF
```

- vm63：/opt/cfg/etcd.config.yml

```
cat > /opt/cfg/etcd.config.yml << EOF 
name: 'vm63'
data-dir: /var/lib/etcd
wal-dir: /var/lib/etcd/wal
snapshot-count: 5000
heartbeat-interval: 100
election-timeout: 1000
quota-backend-bytes: 0
listen-peer-urls: 'https://192.168.26.63:2380'
listen-client-urls: 'https://192.168.26.63:2379,http://127.0.0.1:2379'
max-snapshots: 3
max-wals: 5
cors:
initial-advertise-peer-urls: 'https://192.168.26.63:2380'
advertise-client-urls: 'https://192.168.26.63:2379'
discovery:
discovery-fallback: 'proxy'
discovery-proxy:
discovery-srv:
initial-cluster: 'vm61=https://192.168.26.61:2380,vm62=https://192.168.26.62:2380,vm63=https://192.168.26.63:2380'
initial-cluster-token: 'etcd-k8s-cluster'
initial-cluster-state: 'new'
strict-reconfig-check: false
enable-v2: true
enable-pprof: true
proxy: 'off'
proxy-failure-wait: 5000
proxy-refresh-interval: 30000
proxy-dial-timeout: 1000
proxy-write-timeout: 5000
proxy-read-timeout: 0
client-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
peer-transport-security:
  cert-file: '/opt/cert/etcd.pem'
  key-file: '/opt/cert/etcd-key.pem'
  peer-client-cert-auth: true
  trusted-ca-file: '/opt/cert/etcd-ca.pem'
  auto-tls: true
debug: false
log-package-levels:
log-outputs: [default]
force-new-cluster: false
EOF
```

### 02 创建service、启动、检查

> 在edcd节点vm61、vm62、vm63

```sh
cat > /usr/lib/systemd/system/etcd.service << EOF

[Unit]
Description=Etcd Service
Documentation=https://coreos.com/etcd/docs/latest/
After=network.target

[Service]
Type=notify
ExecStart=/opt/bin/etcd --config-file=/opt/cfg/etcd.config.yml
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
Alias=etcd3.service

EOF
```

> 启动，检查

```sh
]# systemctl daemon-reload
]# systemctl enable --now etcd
]# systemctl status etcd
● etcd.service - Etcd Service
   Loaded: loaded (/usr/lib/systemd/system/etcd.service; enabled; vendor preset: disabled)
   Active: active (running) since Tue 2023-05-02 19:10:06 CST; 1min 21s ago
   ...
]# ETCDCTL_API=3 etcdctl --endpoints="192.168.26.61:2379,192.168.26.62:2379,192.168.26.63:2379" --cacert=/opt/cert/etcd-ca.pem --cert=/opt/cert/etcd.pem --key=/opt/cert/etcd-key.pem  endpoint status --write-out=table
+--------------------+------------------+---------+---------+-----------+------------+-----------+------------+--------------------+--------+
|      ENDPOINT      |        ID        | VERSION | DB SIZE | IS LEADER | IS LEARNER | RAFT TERM | RAFT INDEX | RAFT APPLIED INDEX | ERRORS |
+--------------------+------------------+---------+---------+-----------+------------+-----------+------------+--------------------+--------+
| 192.168.26.61:2379 | bb87b1aeb468213c |   3.5.8 |   20 kB |     false |      false |         2 |          9 |                  9 |        |
| 192.168.26.62:2379 | 1f9eca0441526f21 |   3.5.8 |   20 kB |      true |      false |         2 |          9 |                  9 |        |
| 192.168.26.63:2379 | b16550e98a707c52 |   3.5.8 |   20 kB |     false |      false |         2 |          9 |                  9 |        |
+--------------------+------------------+---------+---------+-----------+------------+-----------+------------+--------------------+--------+
```



## 八、核心组件

```sh
## 解压软件包，并将运行软件放到/opt/bin目录
vm61 app]# tar -xf kubernetes-server-linux-amd64.tar.gz  --strip-components=3 -C /opt/bin kubernetes/server/bin/kube{let,ctl,-apiserver,-controller-manager,-scheduler,-proxy}
]# ls -l /opt/bin/kube*
-rwxr-xr-x 1 root root 129986560 4月  12 20:28 /opt/bin/kube-apiserver
-rwxr-xr-x 1 root root 119361536 4月  12 20:28 /opt/bin/kube-controller-manager
-rwxr-xr-x 1 root root  48037888 4月  12 20:28 /opt/bin/kubectl
-rwxr-xr-x 1 root root 121273208 4月  12 20:28 /opt/bin/kubelet
-rwxr-xr-x 1 root root  45027328 4月  12 20:28 /opt/bin/kube-proxy
-rwxr-xr-x 1 root root  52457472 4月  12 20:28 /opt/bin/kube-scheduler
]# ln -s /opt/bin/kubectl /usr/local/bin/kubectl
]# /opt/bin/kubelet --version
Kubernetes v1.26.4

## 复制软件到其他节点vm62、vm63。与etcd同时解压，一次复制即可。
]# scp -r /opt/bin/ root@vm62:/opt/
]# scp -r /opt/bin/ root@vm63:/opt/
t]# ln -s /opt/bin/kubectl /usr/local/bin/kubectl
```

### 01 Nginx高可用方案

==使用 nginx方案，kube-apiserver中的配置为： `--server=https://127.0.0.1:8443`==

- 安装nginx

```sh
vm62 app]# tar xvf nginx-1.24.0.tar.gz
vm62 app]# cd nginx-1.24.0
vm62 nginx-1.24.0]# ./configure --with-stream --without-http --without-http_uwsgi_module --without-http_scgi_module --without-http_fastcgi_module
vm62 nginx-1.24.0]# make && make install
vm62 nginx-1.24.0]# ls -l /usr/local/nginx
总用量 0
drwxr-xr-x 2 root root 333 5月   2 19:48 conf
drwxr-xr-x 2 root root  40 5月   2 19:48 html
drwxr-xr-x 2 root root   6 5月   2 19:48 logs
drwxr-xr-x 2 root root  19 5月   2 19:48 sbin
vm62 nginx-1.24.0]# scp -r /usr/local/nginx root@vm61:/usr/local/nginx/
vm62 nginx-1.24.0]# scp -r /usr/local/nginx root@vm63:/usr/local/nginx/
```

- nginx配置文件/usr/local/nginx/conf/kube-nginx.con

```ini
# 写入nginx配置文件
cat > /usr/local/nginx/conf/kube-nginx.conf <<EOF
worker_processes 1;
events {
    worker_connections  1024;
}
stream {
    upstream backend {
    	least_conn;
        hash $remote_addr consistent;
        server 192.168.26.61:6443        max_fails=3 fail_timeout=30s;
        server 192.168.26.62:6443        max_fails=3 fail_timeout=30s;
        server 192.168.26.63:6443        max_fails=3 fail_timeout=30s;
    }
    server {
        listen 127.0.0.1:8443;
        proxy_connect_timeout 1s;
        proxy_pass backend;
    }
}
EOF
```

- 启动配置文件/etc/systemd/system/kube-nginx.service

```ini
# 写入启动配置文件
cat > /etc/systemd/system/kube-nginx.service <<EOF
[Unit]
Description=kube-apiserver nginx proxy
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStartPre=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/kube-nginx.conf -p /usr/local/nginx -t
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/kube-nginx.conf -p /usr/local/nginx
ExecReload=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/kube-nginx.conf -p /usr/local/nginx -s reload
PrivateTmp=true
Restart=always
RestartSec=5
StartLimitInterval=0
LimitNOFILE=65536
 
[Install]
WantedBy=multi-user.target
EOF
```

- 设置开机自启

```sh
# 设置开机自启
]# systemctl enable --now  kube-nginx 
]# systemctl restart kube-nginx
]# systemctl status kube-nginx
```

### 02 部署kube-apiserver

- vm61：/usr/lib/systemd/system/kube-apiserver.service

```ini
cat > /usr/lib/systemd/system/kube-apiserver.service << EOF

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-apiserver \\
      --v=2  \\
      --allow-privileged=true  \\
      --bind-address=0.0.0.0  \\
      --secure-port=6443  \\
      --advertise-address=192.168.26.61 \\
      --service-cluster-ip-range=10.96.0.0/16  \\
      --service-node-port-range=30000-32767  \\
      --etcd-servers=https://192.168.26.61:2379,https://192.168.26.62:2379,https://192.168.26.63:2379 \\
      --etcd-cafile=/opt/cert/etcd-ca.pem  \\
      --etcd-certfile=/opt/cert/etcd.pem  \\
      --etcd-keyfile=/opt/cert/etcd-key.pem  \\
      --client-ca-file=/opt/cert/ca.pem  \\
      --tls-cert-file=/opt/cert/apiserver.pem  \\
      --tls-private-key-file=/opt/cert/apiserver-key.pem  \\
      --kubelet-client-certificate=/opt/cert/apiserver.pem  \\
      --kubelet-client-key=/opt/cert/apiserver-key.pem  \\
      --service-account-key-file=/opt/cert/sa.pub  \\
      --service-account-signing-key-file=/opt/cert/sa.key  \\
      --service-account-issuer=https://kubernetes.default.svc.cluster.local \\
      --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname  \\
      --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,ResourceQuota  \
      --authorization-mode=Node,RBAC  \\
      --enable-bootstrap-token-auth=true  \\
      --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem  \\
      --proxy-client-cert-file=/opt/cert/front-proxy-client.pem  \\
      --proxy-client-key-file=/opt/cert/front-proxy-client-key.pem  \\
      --requestheader-allowed-names=aggregator  \\
      --requestheader-group-headers=X-Remote-Group  \\
      --requestheader-extra-headers-prefix=X-Remote-Extra-  \\
      --requestheader-username-headers=X-Remote-User \\
      --enable-aggregator-routing=true

Restart=on-failure
RestartSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

EOF
```

- vm62：/usr/lib/systemd/system/kube-apiserver.service

```ini
cat > /usr/lib/systemd/system/kube-apiserver.service << EOF

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-apiserver \\
      --v=2  \\
      --allow-privileged=true  \\
      --bind-address=0.0.0.0  \\
      --secure-port=6443  \\
      --advertise-address=192.168.26.62 \\
      --service-cluster-ip-range=10.96.0.0/16  \\
      --service-node-port-range=30000-32767  \\
      --etcd-servers=https://192.168.26.61:2379,https://192.168.26.62:2379,https://192.168.26.63:2379 \\
      --etcd-cafile=/opt/cert/etcd-ca.pem  \\
      --etcd-certfile=/opt/cert/etcd.pem  \\
      --etcd-keyfile=/opt/cert/etcd-key.pem  \\
      --client-ca-file=/opt/cert/ca.pem  \\
      --tls-cert-file=/opt/cert/apiserver.pem  \\
      --tls-private-key-file=/opt/cert/apiserver-key.pem  \\
      --kubelet-client-certificate=/opt/cert/apiserver.pem  \\
      --kubelet-client-key=/opt/cert/apiserver-key.pem  \\
      --service-account-key-file=/opt/cert/sa.pub  \\
      --service-account-signing-key-file=/opt/cert/sa.key  \\
      --service-account-issuer=https://kubernetes.default.svc.cluster.local \\
      --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname  \\
      --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,ResourceQuota  \
      --authorization-mode=Node,RBAC  \\
      --enable-bootstrap-token-auth=true  \\
      --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem  \\
      --proxy-client-cert-file=/opt/cert/front-proxy-client.pem  \\
      --proxy-client-key-file=/opt/cert/front-proxy-client-key.pem  \\
      --requestheader-allowed-names=aggregator  \\
      --requestheader-group-headers=X-Remote-Group  \\
      --requestheader-extra-headers-prefix=X-Remote-Extra-  \\
      --requestheader-username-headers=X-Remote-User \\
      --enable-aggregator-routing=true
      # --feature-gates=IPv6DualStack=true
      # --token-auth-file=/opt/cert/token.csv

Restart=on-failure
RestartSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

EOF
```

- vm63：/usr/lib/systemd/system/kube-apiserver.service

```ini
cat > /usr/lib/systemd/system/kube-apiserver.service << EOF

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-apiserver \\
      --v=2  \\
      --allow-privileged=true  \\
      --bind-address=0.0.0.0  \\
      --secure-port=6443  \\
      --advertise-address=192.168.26.63 \\
      --service-cluster-ip-range=10.96.0.0/16  \\
      --service-node-port-range=30000-32767  \\
      --etcd-servers=https://192.168.26.61:2379,https://192.168.26.62:2379,https://192.168.26.63:2379 \\
      --etcd-cafile=/opt/cert/etcd-ca.pem  \\
      --etcd-certfile=/opt/cert/etcd.pem  \\
      --etcd-keyfile=/opt/cert/etcd-key.pem  \\
      --client-ca-file=/opt/cert/ca.pem  \\
      --tls-cert-file=/opt/cert/apiserver.pem  \\
      --tls-private-key-file=/opt/cert/apiserver-key.pem  \\
      --kubelet-client-certificate=/opt/cert/apiserver.pem  \\
      --kubelet-client-key=/opt/cert/apiserver-key.pem  \\
      --service-account-key-file=/opt/cert/sa.pub  \\
      --service-account-signing-key-file=/opt/cert/sa.key  \\
      --service-account-issuer=https://kubernetes.default.svc.cluster.local \\
      --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname  \\
      --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,ResourceQuota  \
      --authorization-mode=Node,RBAC  \\
      --enable-bootstrap-token-auth=true  \\
      --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem  \\
      --proxy-client-cert-file=/opt/cert/front-proxy-client.pem  \\
      --proxy-client-key-file=/opt/cert/front-proxy-client-key.pem  \\
      --requestheader-allowed-names=aggregator  \\
      --requestheader-group-headers=X-Remote-Group  \\
      --requestheader-extra-headers-prefix=X-Remote-Extra-  \\
      --requestheader-username-headers=X-Remote-User \\
      --enable-aggregator-routing=true
      # --feature-gates=IPv6DualStack=true
      # --token-auth-file=/opt/cert/token.csv

Restart=on-failure
RestartSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

EOF
```

- 启动apiserver（所有master节点）

```sh
]# systemctl daemon-reload && systemctl enable --now kube-apiserver

## 注意查看状态是否启动正常
]# systemctl status kube-apiserver
```

### 03 kubectl配置

- 创建admin.kubeconfig。使用 nginx方案，`--server=https://127.0.0.1:8443`。==在一个节点执行一次即可==

```sh
kubectl config set-cluster kubernetes     \
  --certificate-authority=/opt/cert/ca.pem     \
  --embed-certs=true     \
  --server=https://127.0.0.1:8443     \
  --kubeconfig=/opt/cert/admin.kubeconfig

kubectl config set-credentials kubernetes-admin  \
  --client-certificate=/opt/cert/admin.pem     \
  --client-key=/opt/cert/admin-key.pem     \
  --embed-certs=true     \
  --kubeconfig=/opt/cert/admin.kubeconfig

kubectl config set-context kubernetes-admin@kubernetes    \
  --cluster=kubernetes     \
  --user=kubernetes-admin     \
  --kubeconfig=/opt/cert/admin.kubeconfig

kubectl config use-context kubernetes-admin@kubernetes  --kubeconfig=/opt/cert/admin.kubeconfig

]# mkdir ~/.kube
]# cp /opt/cert/admin.kubeconfig ~/.kube/config
]# scp -r ~/.kube root@vm62:~/.
]# scp -r ~/.kube root@vm63:~/.
```

- 配置kubectl子命令补全

```sh
echo 'source <(kubectl completion bash)' >> ~/.bashrc

~]# yum -y install bash-completion
~]# source /usr/share/bash-completion/bash_completion
~]# source <(kubectl completion bash)

~]# kubectl get componentstatuses
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS      MESSAGE                                                                                        ERROR
scheduler            Unhealthy   Get "https://127.0.0.1:10259/healthz": dial tcp 127.0.0.1:10259: connect: connection refused
controller-manager   Unhealthy   Get "https://127.0.0.1:10257/healthz": dial tcp 127.0.0.1:10257: connect: connection refused
etcd-0               Healthy     {"health":"true","reason":""}
etcd-1               Healthy     {"health":"true","reason":""}
etcd-2               Healthy     {"health":"true","reason":""}
```

### 04 部署kube-controller-manager

> 所有master节点配置，且配置相同。
> 10.244.0.0/16为pod网段，按需求设置你自己的网段。

- 创建启动配置：/usr/lib/systemd/system/kube-controller-manager.service

```ini
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF

[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-controller-manager \\
      --v=2 \\
      --bind-address=0.0.0.0 \\
      --root-ca-file=/opt/cert/ca.pem \\
      --cluster-signing-cert-file=/opt/cert/ca.pem \\
      --cluster-signing-key-file=/opt/cert/ca-key.pem \\
      --service-account-private-key-file=/opt/cert/sa.key \\
      --kubeconfig=/opt/cert/controller-manager.kubeconfig \\
      --leader-elect=true \\
      --use-service-account-credentials=true \\
      --node-monitor-grace-period=40s \\
      --node-monitor-period=5s \\
      --controllers=*,bootstrapsigner,tokencleaner \\
      --allocate-node-cidrs=true \\
      --service-cluster-ip-range=10.96.0.0/16 \\
      --cluster-cidr=10.244.0.0/16 \\
      --node-cidr-mask-size-ipv4=24 \\
      --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem 

Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target

EOF
```

- 创建kube-controller-manager.kubeconfig。使用 nginx方案，`--server=https://127.0.0.1:8443`。==在一个节点执行一次即可==

```sh
kubectl config set-cluster kubernetes \
     --certificate-authority=/opt/cert/ca.pem \
     --embed-certs=true \
     --server=https://127.0.0.1:8443 \
     --kubeconfig=/opt/cert/controller-manager.kubeconfig
## 设置一个环境项，一个上下文
kubectl config set-context system:kube-controller-manager@kubernetes \
    --cluster=kubernetes \
    --user=system:kube-controller-manager \
    --kubeconfig=/opt/cert/controller-manager.kubeconfig
## 设置一个用户项
kubectl config set-credentials system:kube-controller-manager \
     --client-certificate=/opt/cert/controller-manager.pem \
     --client-key=/opt/cert/controller-manager-key.pem \
     --embed-certs=true \
     --kubeconfig=/opt/cert/controller-manager.kubeconfig
## 设置默认环境
kubectl config use-context system:kube-controller-manager@kubernetes \
     --kubeconfig=/opt/cert/controller-manager.kubeconfig
     
]# scp /opt/cert/controller-manager.kubeconfig root@vm62:/opt/cert/controller-manager.kubeconfig
]# scp /opt/cert/controller-manager.kubeconfig root@vm63:/opt/cert/controller-manager.kubeconfig
```

- 启动kube-controller-manager，并查看状态

```sh
]# systemctl daemon-reload
]# systemctl enable --now kube-controller-manager
]# systemctl  status kube-controller-manager

]# kubectl get componentstatuses
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS      MESSAGE                                                                                        ERROR
scheduler            Unhealthy   Get "https://127.0.0.1:10259/healthz": dial tcp 127.0.0.1:10259: connect: connection refused
controller-manager   Healthy     ok
etcd-2               Healthy     {"health":"true","reason":""}
etcd-0               Healthy     {"health":"true","reason":""}
etcd-1               Healthy     {"health":"true","reason":""}
```

### 05 部署kube-schedule

- 创建启动配置：/usr/lib/systemd/system/kube-scheduler.service

```ini
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF

[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-scheduler \\
      --v=2 \\
      --bind-address=0.0.0.0 \\
      --leader-elect=true \\
      --kubeconfig=/opt/cert/scheduler.kubeconfig

Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target

EOF
```

- 创建scheduler.kubeconfig。使用 nginx方案，`--server=https://127.0.0.1:8443`。==在一个节点执行一次即可==

```sh
kubectl config set-cluster kubernetes \
     --certificate-authority=/opt/cert/ca.pem \
     --embed-certs=true \
     --server=https://127.0.0.1:8443 \
     --kubeconfig=/opt/cert/scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
     --client-certificate=/opt/cert/scheduler.pem \
     --client-key=/opt/cert/scheduler-key.pem \
     --embed-certs=true \
     --kubeconfig=/opt/cert/scheduler.kubeconfig

kubectl config set-context system:kube-scheduler@kubernetes \
     --cluster=kubernetes \
     --user=system:kube-scheduler \
     --kubeconfig=/opt/cert/scheduler.kubeconfig

kubectl config use-context system:kube-scheduler@kubernetes \
     --kubeconfig=/opt/cert/scheduler.kubeconfig

]# scp /opt/cert/scheduler.kubeconfig  root@vm62:/opt/cert/scheduler.kubeconfig
]# scp /opt/cert/scheduler.kubeconfig  root@vm63:/opt/cert/scheduler.kubeconfig
```

- 启动并查看服务状态

```sh
]# systemctl daemon-reload
]# systemctl enable --now kube-scheduler
]# systemctl status kube-scheduler
]# kubectl get componentstatuses
Warning: v1 ComponentStatus is deprecated in v1.19+
NAME                 STATUS    MESSAGE                         ERROR
scheduler            Healthy   ok
etcd-0               Healthy   {"health":"true","reason":""}
controller-manager   Healthy   ok
etcd-2               Healthy   {"health":"true","reason":""}
etcd-1               Healthy   {"health":"true","reason":""}
```

### 06 配置bootstrapping

- 创建bootstrap-kubelet.kubeconfig。使用 nginx方案，`--server=https://127.0.0.1:8443`。==在一个节点执行一次即可==

```sh
kubectl config set-cluster kubernetes     \
--certificate-authority=/opt/cert/ca.pem     \
--embed-certs=true     --server=https://127.0.0.1:8443     \
--kubeconfig=/opt/cert/bootstrap-kubelet.kubeconfig

kubectl config set-credentials tls-bootstrap-token-user     \
--token=c8ad9c.2e4d610cf3e7426e \
--kubeconfig=/opt/cert/bootstrap-kubelet.kubeconfig

kubectl config set-context tls-bootstrap-token-user@kubernetes     \
--cluster=kubernetes     \
--user=tls-bootstrap-token-user     \
--kubeconfig=/opt/cert/bootstrap-kubelet.kubeconfig

kubectl config use-context tls-bootstrap-token-user@kubernetes     \
--kubeconfig=/opt/cert/bootstrap-kubelet.kubeconfig

]# scp /opt/cert/bootstrap-kubelet.kubeconfig root@vm62:/opt/cert/bootstrap-kubelet.kubeconfig
]# scp /opt/cert/bootstrap-kubelet.kubeconfig root@vm63:/opt/cert/bootstrap-kubelet.kubeconfig
```

==token的位置在bootstrap.secret.yaml，如果修改的话到这个文件修改==

```sh
## 创建token
~]# head -c 16 /dev/urandom | od -An -t x | tr -d ' '
```

- bootstrap.secret.yaml

```sh
vm61 cfg]# kubectl create -f bootstrap.secret.yaml
secret/bootstrap-token-c8ad9c created
clusterrolebinding.rbac.authorization.k8s.io/kubelet-bootstrap created
clusterrolebinding.rbac.authorization.k8s.io/node-autoapprove-bootstrap created
clusterrolebinding.rbac.authorization.k8s.io/node-autoapprove-certificate-rotation created
clusterrole.rbac.authorization.k8s.io/system:kube-apiserver-to-kubelet created
clusterrolebinding.rbac.authorization.k8s.io/system:kube-apiserver created
```

### 07 部署kubelet

- 创建目录

```sh
mkdir -p /var/lib/kubelet /var/log/kubernetes /etc/systemd/system/kubelet.service.d
mkdir -p /opt/kubernetes/manifests/
```

- 启动文件/usr/lib/systemd/system/kubelet.service。使用Containerd作为Runtime。

```ini
cat > /usr/lib/systemd/system/kubelet.service << "EOF"
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=containerd.service
Requires=containerd.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/opt/bin/kubelet \
  --bootstrap-kubeconfig=/opt/cert/bootstrap-kubelet.kubeconfig \
  --cert-dir=/opt/cert \
  --kubeconfig=/opt/cert/kubelet.kubeconfig \
  --config=/opt/cfg/kubelet.json \
  --container-runtime-endpoint=unix:///run/containerd/containerd.sock \
  --root-dir=/etc/cni/net.d \
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

==kubelet.kubeconfig为自动创建的文件，如果已存在就删除==

- 所有k8s节点创建kubelet的配置文件/opt/cfg/kubelet.json

```json
cat > /opt/cfg/kubelet.json << "EOF"
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/opt/cert/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "192.168.26.63",
  "port": 10250,
  "readOnlyPort": 10255,
  "cgroupDriver": "systemd",                    
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "clusterDomain": "cluster.local.",
  "clusterDNS": ["10.96.0.2"]
}
EOF
```

=="address": "192.168.26.61"==；=="address": "192.168.26.62"==；  =="address": "192.168.26.63"==

- 启动

```sh
~]# systemctl daemon-reload
~]# systemctl enable --now kubelet
~]# systemctl status kubelet
~]# kubectl get nodes -o wide
NAME            STATUS   ROLES    AGE   VERSION   INTERNAL-IP     EXTERNAL-IP   OS-IMAGE         KERNEL-VERSION                CONTAINER-RUNTIME
vm61.centos85   Ready    <none>   85s   v1.26.4   192.168.26.61   <none>        CentOS Linux 8   4.18.0-348.7.1.el8_5.x86_64   containerd://1.6.20
vm62.centos85   Ready    <none>   85s   v1.26.4   192.168.26.62   <none>        CentOS Linux 8   4.18.0-348.7.1.el8_5.x86_64   containerd://1.6.20
vm63.centos85   Ready    <none>   85s   v1.26.4   192.168.26.63   <none>        CentOS Linux 8   4.18.0-348.7.1.el8_5.x86_64   containerd://1.6.20
]# kubectl get csr
NAME                                                   AGE   SIGNERNAME                                    REQUESTOR                 REQUESTEDDURATION   CONDITION
node-csr-2x7SUIGAWv2zNCuaojhyUxTSQrdUYfs4YLn0G9UpANA   9h    kubernetes.io/kube-apiserver-client-kubelet   system:bootstrap:c8ad9c   <none>              Approved,Issued
node-csr-BpyggqEtlLaIWNV_r4t-jR3jp1j4pj955CYIFN37igo   35m   kubernetes.io/kube-apiserver-client-kubelet   system:bootstrap:c8ad9c   <none>              Approved,Issued
node-csr-dciUKHdwoL6qu0K3T6xGEMsaXSc3rwFMgwBvGomiPL8   9h    kubernetes.io/kube-apiserver-client-kubelet   system:bootstrap:c8ad9c   <none>              Approved,Issued
node-csr-rcTYmMDLymUw7C43HYguI0ntGT9xFp7CJkZ_8amRn74   9h    kubernetes.io/kube-apiserver-client-kubelet   system:bootstrap:c8ad9c   <none>              Approved,Issued
```

### 08 部署kube-proxy

- 创建kube-proxy.kubeconfig。使用 nginx方案，`--server=https://127.0.0.1:8443`。==在一个节点执行一次即可==

```sh
kubectl config set-cluster kubernetes     \
  --certificate-authority=/opt/cert/ca.pem     \
  --embed-certs=true     \
  --server=https://127.0.0.1:8443     \
  --kubeconfig=/opt/cert/kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy  \
  --client-certificate=/opt/cert/kube-proxy.pem     \
  --client-key=/opt/cert/kube-proxy-key.pem     \
  --embed-certs=true     \
  --kubeconfig=/opt/cert/kube-proxy.kubeconfig

kubectl config set-context kube-proxy@kubernetes    \
  --cluster=kubernetes     \
  --user=kube-proxy     \
  --kubeconfig=/opt/cert/kube-proxy.kubeconfig

kubectl config use-context kube-proxy@kubernetes  --kubeconfig=/opt/cert/kube-proxy.kubeconfig

]# scp  /opt/cert/kube-proxy.kubeconfig root@vm62:/opt/cert/kube-proxy.kubeconfig
]# scp  /opt/cert/kube-proxy.kubeconfig root@vm63:/opt/cert/kube-proxy.kubeconfig
```

- 所有k8s节点添加kube-proxy的service文件

```ini
cat >  /usr/lib/systemd/system/kube-proxy.service << EOF
[Unit]
Description=Kubernetes Kube Proxy
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
ExecStart=/opt/bin/kube-proxy \\
  --config=/opt/cfg/kube-proxy.yaml \\
  --v=2

Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target

EOF
```

- 所有k8s节点添加kube-proxy的配置

```yaml
cat > /opt/cfg/kube-proxy.yaml << EOF
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
clientConnection:
  acceptContentTypes: ""
  burst: 10
  contentType: application/vnd.kubernetes.protobuf
  kubeconfig: /opt/cert/kube-proxy.kubeconfig
  qps: 5
clusterCIDR: 10.244.0.0/16
configSyncPeriod: 15m0s
conntrack:
  max: null
  maxPerCore: 32768
  min: 131072
  tcpCloseWaitTimeout: 1h0m0s
  tcpEstablishedTimeout: 24h0m0s
enableProfiling: false
healthzBindAddress: 0.0.0.0:10256
hostnameOverride: ""
iptables:
  masqueradeAll: false
  masqueradeBit: 14
  minSyncPeriod: 0s
  syncPeriod: 30s
ipvs:
  masqueradeAll: true
  minSyncPeriod: 5s
  scheduler: "rr"
  syncPeriod: 30s
kind: KubeProxyConfiguration
metricsBindAddress: 127.0.0.1:10249
mode: "ipvs"
nodePortAddresses: null
oomScoreAdj: -999
portRange: ""
udpIdleTimeout: 250ms

EOF
```

- 启动

```sh
]# systemctl daemon-reload
]# systemctl enable --now kube-proxy
]# systemctl enable --now kube-proxy
```



## 九、核心插件

### 01 部署网络插件Calico

- 确认libseccomp高于2.4，升级runc。（参见containerd安装）

```sh
]# rpm -qa | grep libseccomp
libseccomp-2.5.1-1.el8.x86_64
```

- 官方下载：https://docs.tigera.io/archive

> https://docs.tigera.io/calico/latest/getting-started/kubernetes/quickstart
>
> https://docs.tigera.io/archive/v3.25/manifests/calico.yaml

```yaml
            - name: CALICO_IPV4POOL_CIDR
              value: "10.244.0.0/16"
```

```sh
]# kubectl apply -f calico3.25.yaml
poddisruptionbudget.policy/calico-kube-controllers created
serviceaccount/calico-kube-controllers created
serviceaccount/calico-node created
configmap/calico-config created
customresourcedefinition.apiextensions.k8s.io/bgpconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/bgppeers.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/blockaffinities.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/caliconodestatuses.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/clusterinformations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/felixconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworksets.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/hostendpoints.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamblocks.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamconfigs.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamhandles.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ippools.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipreservations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/kubecontrollersconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networksets.crd.projectcalico.org created
clusterrole.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrole.rbac.authorization.k8s.io/calico-node created
clusterrolebinding.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrolebinding.rbac.authorization.k8s.io/calico-node created
daemonset.apps/calico-node created
deployment.apps/calico-kube-controllers created
]# watch kubectl get pod -A
]# kubectl get pod -A -o wide
NAMESPACE     NAME                                      READY   STATUS    RESTARTS   AGE     IP              NODE            NOMINATED NODE   READINESS GATES
kube-system   calico-kube-controllers-57b57c56f-nxmql   1/1     Running   0          2m47s   10.88.0.2       vm63.centos85   <none>           <none>
kube-system   calico-node-rtw7w                         1/1     Running   0          2m47s   192.168.26.61   vm61.centos85   <none>           <none>
kube-system   calico-node-vsxbp                         1/1     Running   0          2m47s   192.168.26.62   vm62.centos85   <none>           <none>
kube-system   calico-node-xqgbw                         1/1     Running   0          2m47s   192.168.26.63   vm63.centos85   <none>           <none>
```

- 查看下载的镜像

```sh
vm63 app]# crictl images
IMAGE                                           TAG                 IMAGE ID            SIZE
docker.io/calico/cni                            v3.25.0             d70a5947d57e5       88MB
docker.io/calico/kube-controllers               v3.25.0             5e785d005ccc1       31.3MB
docker.io/calico/node                           v3.25.0             08616d26b8e74       87.2MB
registry.aliyuncs.com/google_containers/pause   3.6                 6270bb605e12e       302kB
```

### 02 部署服务发现插件CoreDNS

- 下载：https://github.com/kubernetes/kubernetes/blob/v1.26.4/cluster/addons/dns/coredns/coredns.yaml.base
- 修改：

```ini
__DNS__DOMAIN__  改为：  cluster.local
__DNS__MEMORY__LIMIT__ 改为： 150Mi
__DNS__SERVER__ 改为： 10.96.0.2
image: registry.cn-hangzhou.aliyuncs.com/chenby/coredns:v1.10.0
```

- 执行：

```sh
vm61 cfg]# kubectl apply -f coredns.yaml
serviceaccount/coredns created
clusterrole.rbac.authorization.k8s.io/system:coredns created
clusterrolebinding.rbac.authorization.k8s.io/system:coredns created
configmap/coredns created
deployment.apps/coredns created
service/kube-dns created

vm63 app]# kubectl get pod -A -o wide
NAMESPACE     NAME                                      READY   STATUS    RESTARTS   AGE   IP               NODE            NOMINATED NODE   READINESS GATES
kube-system   calico-kube-controllers-57b57c56f-nxmql   1/1     Running   0          35m   10.88.0.2        vm63.centos85   <none>           <none>
kube-system   calico-node-rtw7w                         1/1     Running   0          35m   192.168.26.61    vm61.centos85   <none>           <none>
kube-system   calico-node-vsxbp                         1/1     Running   0          35m   192.168.26.62    vm62.centos85   <none>           <none>
kube-system   calico-node-xqgbw                         1/1     Running   0          35m   192.168.26.63    vm63.centos85   <none>           <none>
kube-system   coredns-568bb5dbff-m745q                  1/1     Running   0          62s   10.244.247.193   vm61.centos85   <none>           <none>
```

### 03 部署资源监控插件Metrics-server

> Kubernetes中系统资源的采集均使用Metrics-server，通过Metrics采集节点和Pod的内存、磁盘、CPU和网络的使用率。

- 下载：

> 单机版：https://mirrors.chenby.cn/https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
> 高可用版本：https://mirrors.chenby.cn/https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/high-availability.yaml

- 修改配置：

```sh
vm61 cfg]# vi high-availability.yaml
# 1
        - --cert-dir=/tmp
        - --secure-port=4443
        - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
        - --kubelet-use-node-status-port
        - --metric-resolution=15s
        - --kubelet-insecure-tls
        - --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem
        - --requestheader-username-headers=X-Remote-User
        - --requestheader-group-headers=X-Remote-Group
        - --requestheader-extra-headers-prefix=X-Remote-Extra-
# 2
        volumeMounts:
        - mountPath: /tmp
          name: tmp-dir
        - name: ca-ssl
          mountPath: /opt/cert
# 3
      volumes:
      - emptyDir: {}
        name: tmp-dir
      - name: ca-ssl
        hostPath:
          path: /opt/cert
# 4
apiVersion: policy/v1
kind: PodDisruptionBudget
# 5 修改为image镜像
image: registry.aliyuncs.com/google_containers/metrics-server:v0.6.3
```

- 执行

```sh
vm61 cfg]# kubectl apply -f high-availability.yaml
vm63 app]# kubectl get pod -n kube-system | grep metrics
metrics-server-c4dc587dd-d2q8w            1/1     Running   0          3m38s
metrics-server-c4dc587dd-w99ql            1/1     Running   0          3m38s
vm63 app]# kubectl top node
NAME            CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
vm61.centos85   136m         6%     1351Mi          37%
vm62.centos85   138m         6%     1363Mi          37%
vm63.centos85   124m         6%     1255Mi          34%
vm63 app]# kubectl top pod -A
NAMESPACE     NAME                                      CPU(cores)   MEMORY(bytes)
kube-system   calico-kube-controllers-57b57c56f-nxmql   2m           27Mi
kube-system   calico-node-rtw7w                         33m          154Mi
kube-system   calico-node-vsxbp                         30m          152Mi
kube-system   calico-node-xqgbw                         22m          154Mi
kube-system   coredns-568bb5dbff-m745q                  1m           21Mi
kube-system   metrics-server-c4dc587dd-d2q8w            3m           19Mi
kube-system   metrics-server-c4dc587dd-w99ql            3m           25Mi
```

### 04 部署dashboard

- 下载：https://github.com/kubernetes/dashboard

> https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

- 修改：vm61 cfg]# vi recommended.yaml

```yaml
...
          image: kubernetesui/dashboard:v2.7.0
          imagePullPolicy: IfNotPresent #修改
...
          image: kubernetesui/metrics-scraper:v1.0.8
          imagePullPolicy: IfNotPresent #修改
...
kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  type: NodePort   #新增
  ports:
    - port: 443
      targetPort: 8443
      nodePort: 31235   #新增
  selector:
    k8s-app: kubernetes-dashboard
...
```

- 执行

```sh
vm61 cfg]# kubectl apply -f recommended.yaml
vm63 app]# kubectl get pods,svc -n kubernetes-dashboard
NAME                                            READY   STATUS    RESTARTS   AGE
pod/dashboard-metrics-scraper-7bc864c59-7r2cr   1/1     Running   0          70s
pod/kubernetes-dashboard-7b8b7d8965-6xzlh       1/1     Running   0          70s

NAME                                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)         AGE
service/dashboard-metrics-scraper   ClusterIP   10.96.109.233   <none>        8000/TCP        70s
service/kubernetes-dashboard        NodePort    10.96.38.22     <none>        443:31235/TCP   70s
```

- 创建admin-user：vm61 cfg]# vi dashboard-adminuser.yaml

  > https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
```

```sh
vm61 cfg]# kubectl apply -f dashboard-adminuser.yaml
vm63 app]# kubectl -n kubernetes-dashboard create token admin-user
eyJhbGciOiJSUzI1NiIsImtpZCI6InFnVzJBTS1IbFYtYVdFX1JEazMyYnkzczM4dURTLWlsN0NXQUlRbUUxclkifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgzMDkxNzQwLCJpYXQiOjE2ODMwODgxNDAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhZG1pbi11c2VyIiwidWlkIjoiYjU4YmIxMWMtNTRhYy00ZWMxLTg1YmItYjQ5ZDI5NzU3YThhIn19LCJuYmYiOjE2ODMwODgxNDAsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlcm5ldGVzLWRhc2hib2FyZDphZG1pbi11c2VyIn0.Rp5iJ-Iy1PkUtFdkcbkdPrd-TQHrZQGN2G5aWYv7h-0dnlzoB619FKvxZWuKk8oC1-wET6Y4Fx8Pe7G4eP5FShO09levEY9Yq5PPXNLEicpBhRFB7A7bXUUkCbvZWg1LXpgiF-rzQ-EMRn9ANaQAjlvf0APIAjnUGXm-kmE7uvnEbLqVJJSKdSMHfJ4NvnFw0VSN4PAMA1tmltUXGz0RmmVHddKfWdaLnMvFkah7jf7AtzNXhdHBI_-m_Ir_dGV4MjAZEImXX2mOkIZ8UQ4BedlV1CZowC-OWCZD1IJdqMI3A7kFCTsMw8P_KNodp-i-cuYkFawO82OOWiWn4vi7HA

```

- https://192.168.26.61:31235/

![image-20230503124425296](k8s-v1.26.4 + CentOS-8.5.2111集群部署.assets/image-20230503124425296.png)



## 十、集群验证

### 01 部署应用验证

```yaml
cat >  nginx.yaml  << "EOF"
---
apiVersion: v1
kind: ReplicationController
metadata:
  name: nginx-web
spec:
  replicas: 2
  selector:
    name: nginx
  template:
    metadata:
      labels:
        name: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.19.6
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nodeport
spec:
  ports:
    - port: 80
      targetPort: 80
      nodePort: 30001
      protocol: TCP
  type: NodePort
  selector:
    name: nginx
EOF
```

```sh
vm61 cfg]# kubectl apply -f nginx.yaml
vm61 cfg]# kubectl get pods -o wide
NAME              READY   STATUS              RESTARTS   AGE   IP       NODE            NOMINATED NODE   READINESS GATES
nginx-web-bpmk2   0/1     ContainerCreating   0          8s    <none>   vm62.centos85   <none>           <none>
nginx-web-v6g2n   0/1     ContainerCreating   0          8s    <none>   vm63.centos85   <none>           <none>
vm61 cfg]# kubectl get all
...
vm61 cfg]# kubectl get service
NAME                     TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
kubernetes               ClusterIP   10.96.0.1      <none>        443/TCP        17h
nginx-service-nodeport   NodePort    10.96.253.96   <none>        80:30001/TCP   4m20s
```

浏览器访问：http://192.168.26.63:30001/

### 02 创建3个副本在不同的节点上

```yaml
vm61 cfg]# cat > nginx-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80

EOF
```

```sh
vm61 cfg]# kubectl  apply -f nginx-deployment.yaml
deployment.apps/nginx-deployment created
]# kubectl get pod |grep nginx-deployment
nginx-deployment-7f456874f4-fmqvg   1/1     Running   0          85s
nginx-deployment-7f456874f4-k5kfx   1/1     Running   0          85s
nginx-deployment-7f456874f4-zjrnx   1/1     Running   0          85s
vm61 cfg]# kubectl delete -f nginx-deployment.yaml
```

### 03 部署pod验证

- vm61 cfg]# vi busybox.yaml

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - name: busybox
    image: docker.io/library/busybox:1.28
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
```

```sh
vm61 cfg]# kubectl apply -f busybox.yaml
pod/busybox created
[root@vm61 cfg]# kubectl  get pod
NAME              READY   STATUS    RESTARTS   AGE
busybox           1/1     Running   0          10s
nginx-web-bpmk2   1/1     Running   0          6m16s
nginx-web-v6g2n   1/1     Running   0          6m16s
```

### 04 用pod解析默认命名空间中的kubernetes

```sh
]# kubectl get svc
NAME                     TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
kubernetes               ClusterIP   10.96.0.1      <none>        443/TCP        17h
nginx-service-nodeport   NodePort    10.96.253.96   <none>        80:30001/TCP   7m57s

]# kubectl exec  busybox -n default -- nslookup kubernetes
Server:    10.96.0.2
Address 1: 10.96.0.2 kube-dns.kube-system.svc.cluster.local

Name:      kubernetes
Address 1: 10.96.0.1 kubernetes.default.svc.cluster.local
```

### 05 测试跨命名空间是否可以解析

```sh
]# kubectl exec  busybox -n default -- nslookup kube-dns.kube-system
Server:    10.96.0.2
Address 1: 10.96.0.2 kube-dns.kube-system.svc.cluster.local

Name:      kube-dns.kube-system
Address 1: 10.96.0.2 kube-dns.kube-system.svc.cluster.local
```

### 06 每个节点都必须要能访问Kubernetes的kubernetes svc 443和kube-dns的service 53

```sh
]# kubectl get svc -A
NAMESPACE              NAME                        TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                  AGE
default                kubernetes                  ClusterIP   10.96.0.1       <none>        443/TCP                  17h
default                nginx-service-nodeport      NodePort    10.96.253.96    <none>        80:30001/TCP             11m
kube-system            kube-dns                    ClusterIP   10.96.0.2       <none>        53/UDP,53/TCP,9153/TCP   173m
kube-system            metrics-server              ClusterIP   10.96.28.97     <none>        443/TCP                  135m
kubernetes-dashboard   dashboard-metrics-scraper   ClusterIP   10.96.109.233   <none>        8000/TCP                 86m
kubernetes-dashboard   kubernetes-dashboard        NodePort    10.96.38.22     <none>        443:31235/TCP            86m
```

```sh
]# telnet 10.96.0.1 443
Trying 10.96.0.1...
Connected to 10.96.0.1.
Escape character is '^]'.

]# telnet 10.96.0.2 53
Trying 10.96.0.2...
Connected to 10.96.0.2.
Escape character is '^]'.

]# curl 10.96.0.2:53
curl: (52) Empty reply from server
```

### 07 Pod和其它主机及Pod之间能通

```sh
]# kubectl get po -owide
NAME              READY   STATUS    RESTARTS   AGE   IP               NODE            NOMINATED NODE   READINESS GATES
busybox           1/1     Running   0          10m   10.244.247.195   vm61.centos85   <none>           <none>
nginx-web-bpmk2   1/1     Running   0          16m   10.244.175.195   vm62.centos85   <none>           <none>
nginx-web-v6g2n   1/1     Running   0          16m   10.244.50.130    vm63.centos85   <none>           <none>

]# kubectl get po -n kube-system -owide
NAME                                      READY   STATUS    RESTARTS   AGE     IP               NODE            NOMINATED NODE   READINESS GATES
calico-kube-controllers-57b57c56f-nxmql   1/1     Running   0          3h34m   10.88.0.2        vm63.centos85   <none>           <none>
calico-node-rtw7w                         1/1     Running   0          3h34m   192.168.26.61    vm61.centos85   <none>           <none>
calico-node-vsxbp                         1/1     Running   0          3h34m   192.168.26.62    vm62.centos85   <none>           <none>
calico-node-xqgbw                         1/1     Running   0          3h34m   192.168.26.63    vm63.centos85   <none>           <none>
coredns-568bb5dbff-m745q                  1/1     Running   0          179m    10.244.247.193   vm61.centos85   <none>           <none>
metrics-server-c4dc587dd-d2q8w            1/1     Running   0          141m    10.244.175.193   vm62.centos85   <none>           <none>
metrics-server-c4dc587dd-w99ql            1/1     Running   0          141m    10.244.50.129    vm63.centos85   <none>           <none>

```

进入busybox ping其他节点上的pod。可以连通证明这个pod是可以跨命名空间和跨主机通信的。

```sh
]# kubectl exec -ti busybox -- sh
/ # ping 192.168.26.63
PING 192.168.26.63 (192.168.26.63): 56 data bytes
64 bytes from 192.168.26.63: seq=0 ttl=63 time=4.021 ms
64 bytes from 192.168.26.63: seq=1 ttl=63 time=0.407 ms
...
/ # ping 10.244.175.195
PING 10.244.175.195 (10.244.175.195): 56 data bytes
64 bytes from 10.244.175.195: seq=0 ttl=62 time=0.526 ms
64 bytes from 10.244.175.195: seq=1 ttl=62 time=0.479 ms
...
```



## yaml文件

### bootstrap.secret.yaml

```yaml
cat > bootstrap.secret.yaml << EOF 
apiVersion: v1
kind: Secret
metadata:
  name: bootstrap-token-c8ad9c
  namespace: kube-system
type: bootstrap.kubernetes.io/token
stringData:
  description: "The default bootstrap token generated by 'kubelet '."
  token-id: c8ad9c
  token-secret: 2e4d610cf3e7426e
  usage-bootstrap-authentication: "true"
  usage-bootstrap-signing: "true"
  auth-extra-groups:  system:bootstrappers:default-node-token,system:bootstrappers:worker,system:bootstrappers:ingress
 
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubelet-bootstrap
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:node-bootstrapper
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:bootstrappers:default-node-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-autoapprove-bootstrap
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:certificates.k8s.io:certificatesigningrequests:nodeclient
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:bootstrappers:default-node-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-autoapprove-certificate-rotation
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:certificates.k8s.io:certificatesigningrequests:selfnodeclient
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:nodes
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kube-apiserver
EOF
```

### coredns.yaml

```yml
cat > coredns.yaml << EOF 
apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
rules:
  - apiGroups:
    - ""
    resources:
    - endpoints
    - services
    - pods
    - namespaces
    verbs:
    - list
    - watch
  - apiGroups:
    - discovery.k8s.io
    resources:
    - endpointslices
    verbs:
    - list
    - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
          lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        forward . /etc/resolv.conf {
          max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/name: "CoreDNS"
spec:
  # replicas: not specified here:
  # 1. Default is 1.
  # 2. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      nodeSelector:
        kubernetes.io/os: linux
      affinity:
         podAntiAffinity:
           preferredDuringSchedulingIgnoredDuringExecution:
           - weight: 100
             podAffinityTerm:
               labelSelector:
                 matchExpressions:
                   - key: k8s-app
                     operator: In
                     values: ["kube-dns"]
               topologyKey: kubernetes.io/hostname
      containers:
      - name: coredns
        image: registry.aliyuncs.com/google_containers/coredns:v1.10.0
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /ready
            port: 8181
            scheme: HTTP
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
---
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.96.0.2 
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
EOF
```

### metrics-server.yaml

```yml
cat > metrics-server.yaml << EOF 
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    k8s-app: metrics-server
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
    rbac.authorization.k8s.io/aggregate-to-view: "true"
  name: system:aggregated-metrics-reader
rules:
- apiGroups:
  - metrics.k8s.io
  resources:
  - pods
  - nodes
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    k8s-app: metrics-server
  name: system:metrics-server
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - nodes
  - nodes/stats
  - namespaces
  - configmaps
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server-auth-reader
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-apiserver-authentication-reader
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server:system:auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: system:metrics-server
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:metrics-server
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: https
  selector:
    k8s-app: metrics-server
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: metrics-server
  strategy:
    rollingUpdate:
      maxUnavailable: 0
  template:
    metadata:
      labels:
        k8s-app: metrics-server
    spec:
      containers:
      - args:
        - --cert-dir=/tmp
        - --secure-port=4443
        - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
        - --kubelet-use-node-status-port
        - --metric-resolution=15s
        - --kubelet-insecure-tls
        - --requestheader-client-ca-file=/opt/cert/front-proxy-ca.pem # change to front-proxy-ca.crt for kubeadm
        - --requestheader-username-headers=X-Remote-User
        - --requestheader-group-headers=X-Remote-Group
        - --requestheader-extra-headers-prefix=X-Remote-Extra-
        image: registry.cn-hangzhou.aliyuncs.com/chenby/metrics-server:v0.5.2
        imagePullPolicy: IfNotPresent
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /livez
            port: https
            scheme: HTTPS
          periodSeconds: 10
        name: metrics-server
        ports:
        - containerPort: 4443
          name: https
          protocol: TCP
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /readyz
            port: https
            scheme: HTTPS
          initialDelaySeconds: 20
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 200Mi
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        volumeMounts:
        - mountPath: /tmp
          name: tmp-dir
        - name: ca-ssl
          mountPath: /opt/cert
      nodeSelector:
        kubernetes.io/os: linux
      priorityClassName: system-cluster-critical
      serviceAccountName: metrics-server
      volumes:
      - emptyDir: {}
        name: tmp-dir
      - name: ca-ssl
        hostPath:
          path: /opt/cert

---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  labels:
    k8s-app: metrics-server
  name: v1beta1.metrics.k8s.io
spec:
  group: metrics.k8s.io
  groupPriorityMinimum: 100
  insecureSkipTLSVerify: true
  service:
    name: metrics-server
    namespace: kube-system
  version: v1beta1
  versionPriority: 100
EOF
```



## 附：ipvs安装工具

```sh
~]# yum install ipvsadm ipset sysstat conntrack libseccomp -y
上次元数据过期检查：1 day, 1:43:41 前，执行于 2023年04月27日 星期四 15时32分00秒。
软件包 ipset-7.1-1.el8.x86_64 已安装。
软件包 libseccomp-2.5.1-1.el8.x86_64 已安装。
依赖关系解决。
==================================================================================================================================================
 软件包                                 架构                   版本                                               仓库                       大小
==================================================================================================================================================
安装:
 conntrack-tools                        x86_64                 1.4.4-10.el8                                       baseos                    204 k
 ipvsadm                                x86_64                 1.31-1.el8                                         appstream                  59 k
 sysstat                                x86_64                 11.7.3-6.el8                                       appstream                 425 k
安装依赖关系:
 libnetfilter_cthelper                  x86_64                 1.0.0-15.el8                                       baseos                     24 k
 libnetfilter_cttimeout                 x86_64                 1.0.0-11.el8                                       baseos                     24 k
 libnetfilter_queue                     x86_64                 1.0.4-3.el8                                        baseos                     31 k
 lm_sensors-libs                        x86_64                 3.4.0-23.20180522git70f7e08.el8                    baseos                     59 k

事务概要
==================================================================================================================================================
安装  7 软件包

总下载：827 k
安装大小：2.3 M
下载软件包：
(1/7): ipvsadm-1.31-1.el8.x86_64.rpm                                                                              258 kB/s |  59 kB     00:00
(2/7): libnetfilter_cthelper-1.0.0-15.el8.x86_64.rpm                                                              402 kB/s |  24 kB     00:00
(3/7): conntrack-tools-1.4.4-10.el8.x86_64.rpm                                                                    671 kB/s | 204 kB     00:00
(4/7): libnetfilter_cttimeout-1.0.0-11.el8.x86_64.rpm                                                             417 kB/s |  24 kB     00:00
(5/7): libnetfilter_queue-1.0.4-3.el8.x86_64.rpm                                                                  428 kB/s |  31 kB     00:00
(6/7): lm_sensors-libs-3.4.0-23.20180522git70f7e08.el8.x86_64.rpm                                                 595 kB/s |  59 kB     00:00
(7/7): sysstat-11.7.3-6.el8.x86_64.rpm                                                                            770 kB/s | 425 kB     00:00
--------------------------------------------------------------------------------------------------------------------------------------------------
总计                                                                                                              1.4 MB/s | 827 kB     00:00
运行事务检查
事务检查成功。
运行事务测试
事务测试成功。
运行事务
  准备中  :                                                                                                                                   1/1
  安装    : lm_sensors-libs-3.4.0-23.20180522git70f7e08.el8.x86_64                                                                            1/7
  运行脚本: lm_sensors-libs-3.4.0-23.20180522git70f7e08.el8.x86_64                                                                            1/7
  安装    : libnetfilter_queue-1.0.4-3.el8.x86_64                                                                                             2/7
  运行脚本: libnetfilter_queue-1.0.4-3.el8.x86_64                                                                                             2/7
  安装    : libnetfilter_cttimeout-1.0.0-11.el8.x86_64                                                                                        3/7
  运行脚本: libnetfilter_cttimeout-1.0.0-11.el8.x86_64                                                                                        3/7
  安装    : libnetfilter_cthelper-1.0.0-15.el8.x86_64                                                                                         4/7
  运行脚本: libnetfilter_cthelper-1.0.0-15.el8.x86_64                                                                                         4/7
  安装    : conntrack-tools-1.4.4-10.el8.x86_64                                                                                               5/7
  运行脚本: conntrack-tools-1.4.4-10.el8.x86_64                                                                                               5/7
  安装    : sysstat-11.7.3-6.el8.x86_64                                                                                                       6/7
  运行脚本: sysstat-11.7.3-6.el8.x86_64                                                                                                       6/7
  安装    : ipvsadm-1.31-1.el8.x86_64                                                                                                         7/7
  运行脚本: ipvsadm-1.31-1.el8.x86_64                                                                                                         7/7
  验证    : ipvsadm-1.31-1.el8.x86_64                                                                                                         1/7
  验证    : sysstat-11.7.3-6.el8.x86_64                                                                                                       2/7
  验证    : conntrack-tools-1.4.4-10.el8.x86_64                                                                                               3/7
  验证    : libnetfilter_cthelper-1.0.0-15.el8.x86_64                                                                                         4/7
  验证    : libnetfilter_cttimeout-1.0.0-11.el8.x86_64                                                                                        5/7
  验证    : libnetfilter_queue-1.0.4-3.el8.x86_64                                                                                             6/7
  验证    : lm_sensors-libs-3.4.0-23.20180522git70f7e08.el8.x86_64                                                                            7/7

已安装:
  conntrack-tools-1.4.4-10.el8.x86_64           ipvsadm-1.31-1.el8.x86_64                libnetfilter_cthelper-1.0.0-15.el8.x86_64
  libnetfilter_cttimeout-1.0.0-11.el8.x86_64    libnetfilter_queue-1.0.4-3.el8.x86_64    lm_sensors-libs-3.4.0-23.20180522git70f7e08.el8.x86_64
  sysstat-11.7.3-6.el8.x86_64

完毕！
```

