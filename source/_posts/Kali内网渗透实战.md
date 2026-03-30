# Kali 内网渗透实战：从局域网扫描到网络拓扑生成

最近在实验室做内网渗透练习，从**虚拟机桥接配置**、**跨网段设备扫描**、**网关/DHCP定位**到**SSH老设备兼容**、**网络拓扑绘制**踩了一堆坑。把完整流程整理成这篇实战博客，既能帮到同样在练手的朋友，也方便自己复盘。

## 一、环境说明

- 虚拟机：Kali Linux（VirtualBox）

- 网络模式：**桥接模式**（关键：Host-Only 无法扫真实局域网）

- 本地网段：192.168.4.0/24（桥接）,10.0.2.15/24 （NAT）

- 实验网段：172.16.1.0/24、172.16.2.0/24（三层路由互通），172.16.2.254（网关）

- 核心目标：发现内网设备 → 定位网关/DHCP → 生成网络拓扑

---

## 二、第一步：Kali 桥接配置（扫真实内网的前提）

### 1. 三种网络模式对比
| 模式       | 能否访问外网 | 能否扫描局域网设备 | 适用场景       |
|------------|--------------|--------------------|----------------|
| Host-Only  | ❌           | 仅物理机↔虚拟机    | 本地测试       |
| NAT        | ✅           | ❌                 | 虚拟机上网     |
| 桥接       | ✅           | ✅                 | 内网渗透扫描   |

### 2. 桥接设置

VirtualBox 设置 → 网络 → 桥接模式


查看 IP：`ip a`，出现和物理机同网段 IP（如 192.168.4.27）即成功。

---


## 三、第二步：局域网设备扫描（同网段/跨网段区别）

### 1. 同网段扫描（最准：arp-scan）

ARP 协议仅在**二层局域网**有效，不受防火墙限制，几乎 100% 发现设备。

```bash
# 先查看网卡
ip a
# 指定网卡扫描（我的网卡是 eth2）
sudo arp-scan -I eth2 --localnet
```

⚠️ 常见警告：`Cannot open MAC/Vendor file`

不影响扫描，修复权限即可：

```bash
sudo chmod 644 /usr/share/arp-scan/*.txt
```

### 2. 跨网段扫描（只能用 nmap）

**ARP 跨网段无效**，172.16.2.0/24 必须用 IP 层扫描：

```bash
# 只扫存活主机，不扫端口
sudo nmap -sn -T4 172.16.2.0/24
```
---


## 四、第三步：定位网关与核心设备

### 1. 找到网关


Kali：`ip route`

返回如下结果
```bash
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100 
default via 192.168.4.1 dev eth2 proto dhcp src 192.168.4.27 metric 102 
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100 
192.168.4.0/24 dev eth2 proto kernel scope link src 192.168.4.27 metric 102 
192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.101 metric 101
```
我的虚拟机网关：**192.168.4.1** 和 **10.0.2.2**

注意：NAT模式虽能访问172.16.5.254，但存在局限性——无法直接扫描该网段其他设备（受NAT转发限制），若需进行内网渗透扫描，仍建议优先使用桥接模式（eth2网卡），避免路由冲突。
### 2. 调整网关优先级
编辑网卡配置
```bash
sudo nano /etc/network/interfaces
```
在对应接口下添加 metric：
```ini
auto eth2
iface eth2 inet dhcp
    metric 50  # 接口默认路由 metric
```
重启网络生效：
```bash
sudo systemctl restart networking
```

#### 3. 验证调整结果（正常状态）

调整后，查看路由表，确认eth2优先级高于eth0：

```bash
ip route show
# 正常路由表输出（eth2 metric 60 优先于 eth0 metric 100）
default via 192.168.4.1 dev eth2 metric 60 
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100 
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100 
192.168.4.0/24 dev eth2 proto kernel scope link src 192.168.4.27 metric 102 
192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.101 metric 101
```

再次执行traceroute -I 172.16.2.254，输出完全正常，显示正确的两跳路径：
(-I 表示使用ICMP包探测，-T 表示用TCP模式，不加参数表示用UDP包探测)
```plain
traceroute to 172.16.2.254 (172.16.2.254), 30 hops max, 60 byte packets
 1  localhost (192.168.4.1)  236.261 ms  236.092 ms  236.000 ms  # 第1跳：桥接网关（eth2）
 2  localhost (172.16.2.254)  235.928 ms  235.851 ms  235.777 ms  # 第2跳：目标设备
```

#### 4. 关键总结

- 多网卡（NAT+桥接）环境，必须调整**metric值**，让桥接网卡优先级高于NAT网卡，避免流量走错。

- traceroute显示2跳是正常现象：因网关（192.168.4.1）与目标设备（172.16.2.254）处于同一内网三层环境，中间设备不返回ICMP，无需担心。

- 此时执行抓包命令（sudo tcpdump -i eth2 icmp and host 172.16.2.254），可正常抓取到数据包，验证流量走eth2网卡。



### 3. 扫描网关开放端口

```bash
nmap -T4 -F 172.16.2.254
```

开放端口：

- 22/tcp：SSH

- 23/tcp：Telnet

- 8443/8888：服务端口

---

## 五、第三步：快速生成网络拓扑图

### 最简方案：Nmap + Draw.io

```bash
# 导出扫描结果
sudo nmap -sn -oG ips.txt 172.16.2.0/24
```

打开[diagrams.net](https://app.diagrams.net)，拖拽设备图标连线即可。