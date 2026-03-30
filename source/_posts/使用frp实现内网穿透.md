---
title: 使用FRP实现内网穿透
tags: [FRP, 内网穿透]
id: '99'
categories: 后端开发
date: 2025-04-29 23:11:02
---

在日常开发中，经常会遇到需要外部服务调用本地项目的场景——比如测试支付接口时，支付宝、微信的回调服务器无法直接访问我们本地的开发环境。这时候，**内网穿透**就成了最优解，而FRP（Fast Reverse Proxy）就是一款轻量、易用的内网穿透工具，今天就来详细分享如何用FRP实现内网穿透，解决本地接口回调验证的问题。

## 一、FRP工作原理（简单理解）

FRP分为服务端和客户端两部分，核心逻辑很简单：

- 服务端部署在有公网IP的服务器上，监听指定端口（本文用7070端口）；

- 客户端部署在本地设备（开发机）上，通过7070端口与服务端建立连接；

- 服务端会为本地服务映射一个公网端口/域名，当外部请求访问这个公网地址时，服务端会将请求转发给客户端，再由客户端转发到本地对应的服务端口（本文用8848端口）。

简单说，就是通过FRP搭建一座“桥梁”，让外部网络能通过公网服务器，找到我们本地的服务。

## 二、服务端配置（公网服务器）

服务端需要部署在有公网IP的服务器上（比如阿里云、腾讯云轻量应用服务器），系统推荐Linux（本文以Linux amd64为例）。

### 1. 下载并解压FRP

进入FRP官方GitHub仓库，下载对应系统的安装包，这里选用v0.62.1版本（稳定版），执行以下命令：

```bash
# 下载FRP服务端安装包
wget https://github.com/fatedier/frp/releases/download/v0.62.1/frp_0.62.1_linux_amd64.tar.gz

# 解压安装包
tar -xvzf frp_0.62.1_linux_amd64.tar.gz

# 进入解压后的目录（目录名可自行修改）
cd frp_0.62.1_linux_amd64
```

### 2. 编辑服务端配置文件（frps.toml）

FRP服务端的配置文件是frps.toml（frps即frp server），用vim编辑，核心配置如下（注释已简化，关键配置标红）：

```text
# 绑定监听地址（默认0.0.0.0，监听所有IP）
bindAddr = "0.0.0.0"
# 客户端连接服务端的端口（需开放服务器防火墙该端口）
bindPort = 7070

# HTTP/HTTPS映射端口（用于域名访问，无域名可忽略）
vhostHTTPPort = 8080
vhostHTTPSPort = 8443

# 子域名配置（有域名才需要，无域名请删除此行）
subDomainHost = "example.com"  # 替换为你的真实域名

# Web管理面板配置（可选，用于监控FRP连接状态）
webServer.addr = "0.0.0.0"
webServer.port = 7500          # 面板访问端口
webServer.user = "user_example"# 面板账号（自定义）
webServer.password = "password_example" # 面板密码（自定义）

# 身份验证（防止非法客户端连接，必须配置）
auth.method = "token"
auth.token = "token_example"   # 自定义token，客户端需与之一致
```

### 3. 启动服务端并后台运行

为了避免关闭终端后FRP服务停止，推荐用nohup命令后台启动，同时输出日志便于排查问题：

```bash
# 后台启动FRP服务端，日志输出到frps.log
nohup ./frps -c frps.toml > frps.log 2>&1 
```

启动后，可通过命令`ps -ef | grep frps` 查看服务是否正常运行。

## 三、客户端配置（本地开发机）

客户端部署在自己的开发机上，根据系统（Windows、Mac、Linux）下载对应版本的FRP安装包，本文以Windows为例。

### 1. 下载FRP客户端

访问FRP官方GitHub仓库：[https://github.com/fatedier/frp/releases](https://github.com/fatedier/frp/releases)，下载对应系统的安装包（比如Windows amd64版本），解压后找到frpc.toml文件（frpc即frp client）。

### 2. 编辑客户端配置文件（frpc.toml）

核心配置需与服务端保持一致，关键配置如下（根据自身情况修改）：

```text
# 服务端公网地址（服务器IP或域名）
serverAddr = "example.com"  # 替换为你的服务器IP/域名
# 服务端监听端口（与服务端bindPort一致）
serverPort = 7070

# 连接协议（默认tcp即可）
transport.protocol = "tcp"

# 身份验证（与服务端token完全一致）
auth.method = "token"
auth.token = "token_example"

# 代理配置（核心部分）
[[proxies]]
name = "rocketcat"  # 代理名称（自定义，便于识别）
type = "http"       # 代理类型：有域名用http，无域名用tcp
localIP = "127.0.0.1"  # 本地服务IP（默认127.0.0.1即可）
localPort = 8848       # 本地服务端口（替换为你的项目端口）
subdomain = "rocket"   # 子域名（有域名时配置，访问地址为rocket.example.com）

# 无域名、IP直连配置（可选，需删除上方subdomain配置）
# type = "tcp"
# remotePort = 8848  # 公网映射端口，与本地端口一致
```

注意：如果没有域名，直接用IP+端口访问，需将type改为tcp，删除subdomain配置，添加remotePort配置（与localPort一致），同时删除服务端的subDomainHost配置。

### 3. 启动客户端

打开Windows命令提示符（CMD），进入FRP客户端解压目录，执行以下命令启动客户端：

```bash
frpc.exe -c frpc.toml
```

启动成功后，会显示“successfully connected to server”，表示客户端与服务端已建立连接。

## 四、验证内网穿透是否成功

按照以下步骤验证，确保穿透生效：

1. 本地启动项目，确保项目监听8848端口（与客户端localPort一致）；

2. 开放本地防火墙8848端口（避免本地服务被防火墙拦截）；

3. 访问FRP管理面板：`http://服务器IP:7500`，输入账号密码，可看到客户端连接状态（显示“online”即为正常）；

4. 外部访问测试：有域名则访问`rocket.example.com:8080`，无域名则访问 `服务器IP:8848`；

5. 预期结果：访问后能看到本地项目的页面，说明内网穿透成功。

（附FRP面板连接成功截图）



## 五、常见问题排查

- 客户端连接失败：检查服务端IP、端口是否正确，服务器防火墙是否开放7070、8080（或8848）端口，token是否与服务端一致；

- 外部无法访问：检查本地项目是否正常启动，本地防火墙是否开放对应端口，客户端配置的localPort是否与项目端口一致；

- 域名无法访问：检查域名是否解析到服务器IP，服务端subDomainHost配置是否正确，客户端subdomain是否匹配。

## 总结

FRP是一款非常实用的内网穿透工具，不仅能解决支付回调测试的问题，还能用于本地项目远程调试、内网设备远程访问等场景。整个配置过程并不复杂，核心是保证服务端和客户端的配置一致，开放对应的防火墙端口。按照本文步骤操作，基本能一次性配置成功，有问题可以在评论区交流~