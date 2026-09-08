# 狩猎模式集（索图外勤）

> 蒸馏自索图内置规则与真实应急案件。每条：模式 / rg 或 SQL 实现 / 判定要点（怎么区分信号和噪音）。
> 所有命中都是候选，不是结论。

## 一、签名模式（rg 多模式一把扫）

```bash
rg -n -i \
  -e 'union(\s|\+|%20)*(all(\s|\+|%20)+)?select' \   # SQLi UNION
  -e 'sleep\s*\(|benchmark\s*\(|waitfor(\s|%20)+delay' \  # SQLi 时间盲注
  -e '\.\./|\.\.%2f|%2e%2e' \                        # 路径穿越(含编码变体)
  -e '/etc/passwd\b|/etc/shadow\b|boot\.ini|win\.ini' \  # 敏感文件(带 \b: /etc/shadowd 之类不误配)
  -e 'sqlmap|nikto|acunetix|netsparker|w3af|masscan|nuclei|gobuster|dirbuster' \  # 扫描器 UA
  -e 'Mozi\.' \                                          # Mozi 载荷(不带点会误配 Mozilla!)
  -e 'eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec' \  # 代码执行特征
  -e '\.git/|\.env|\.svn/|/wp-admin|/wp-login|/phpmyadmin' \  # 敏感路径探测
  target.log
```

判定要点：
- 扫描器 UA 命中**先看来源 IP 是不是己方漏扫器/监控**（内部 IP + 规律间隔 = 大概率是自己人）；
- 路径穿越命中 404 居多=扫描噪音；命中且 200 = 重点复核；
- SQLi 时间盲注：sleep(5) 出现在 query 里 + 响应时间真的变长才算数（看日志有没有响应时间字段）。

## 二、统计异常（duckdb）

### 速率突刺（爆破/扫描前奏）
按分钟桶计数，某 IP 某分钟请求数超其自身基线一个数量级 → 候选。
判定：爬虫也会突刺——看 UA 和路径分布，单一路径+高频=更像爆破。

### 同键异值分化（0day 狩猎模式，实战验证）
同 path 同 IP 同 UA，不同 method 的返回字节数均值差 ≥3 倍：
```sql
WITH g AS (
  SELECT regexp_extract(line,'"(\S+)\s(\S+)',1) AS method,
         regexp_extract(line,'"(\S+)\s(\S+)',2) AS path,
         regexp_extract(line,'^(\S+)',1) AS ip,
         try_cast(regexp_extract(line,'"\s\d{3}\s(\d+)',1) AS BIGINT) AS bytes
  FROM read_csv(...) )
SELECT path, ip, method, count(*) n, avg(bytes) avg_b
FROM g GROUP BY 1,2,3 HAVING count(*) >= 5 ORDER BY path, ip;
-- 同 path+ip 下不同 method 的 avg_b 比值 >=3 → 候选
```
判定：正常业务 GET/POST 返回体也可能天然不同——命中只说明「这个端点行为不统一」，人去看路径像不像业务正常端点。

### 爆破成功链（链式 motif）
同 src_ip 对同 path：先 ≥5 次失败响应，最后一次失败后 5 分钟内出现成功响应 → **高优先候选**。
**先确认目标应用的成功/失败语义再写模式**：不是所有应用都用 401/200——
有应用登录失败返回 200（重渲染登录页）、成功返回 302 跳转（2026-09-08 验收实测案例，
原始 401→200 模式零命中，按 200×N→302 适配后命中真实爆破链）。认证类路径先抽样
人工确认语义，再定模式。
判定：正常用户输错密码再登录也符合——查该账户后续行为（有没有异常操作），别只看链本身。

### 周期信标（C2 beacon 弱信号）
同 IP+path 请求间隔变异系数 ≤0.2、次数 ≥6、首尾跨度 ≥5 分钟。
**SQL 里必须 `WHERE path <> ''`**——空 path（畸形行/CONNECT 探测）会成组霸占
候选前排（2026-09-08 回归实测）。
判定：心跳/健康检查/监控轮询全是周期信号——这是最弱的一类，先查 IP 归属（内网监控？云健康检查？）再决定动不动它。

### 稀有 UA 跨 IP（疑似同源，概率性弱信号）
同一 UA 串（全局出现 <50 次）出现在 ≥2 个不同 src_ip。
**前置过滤必须做**（2026-09-08 回归实测：不过滤时命中全是 30~46 次的常见浏览器
UA，噪音率 100%）：先排除 `Mozilla/|Chrome/|Safari/|Firefox/|Edge/` 系，再看剩余。
判定：常见浏览器 UA 不算（稀有度闸就是为了滤它们）；工具默认 UA（sqlmap 等）跨 IP = 多跳板或代理池，写「疑似同源」，**永不写「同一攻击者」**。

### 同键尺寸离群（尺寸异常顶出语义事件）
同 path 同 method 同状态码的请求，返回字节偏离组内中位数 3 倍以上：
```sql
WITH g AS (
  SELECT regexp_extract(line,'"(GET|POST|PUT|DELETE|HEAD)\s(\S+)',2) AS path,
         regexp_extract(line,'^(\S+)',1) AS ip,
         try_cast(regexp_extract(line,'"\s\d{3}\s(\d+)',1) AS BIGINT) AS bytes
  FROM read_csv(...) ),               -- 行模式惯用法见 tools.md
med AS (
  SELECT path, count(*) n, median(bytes) med_b FROM g
  GROUP BY path HAVING count(*) >= 50 )
SELECT g.path, g.ip, g.bytes, med.med_b, round(g.bytes*1.0/med.med_b,1) AS ratio
FROM g JOIN med ON g.path=med.path
WHERE g.bytes > 3*med.med_b OR g.bytes*3 < med.med_b;
```
判定：偏离中位数说明「这个端点这次干了不一样的事」——配合时间窗看上下文；
静态资源压缩/网络中断也会离群，先看 Content-Type 和是否单次。

### 跨源实体联动（多源场景的杀手锏）
同一实体（IP/账户/UA/文件名）出现在 ≥2 个日志源，自动串联：
```sql
SELECT ip, count(DISTINCT src) AS files, count(*) n FROM (
  SELECT regexp_extract(line,'^(\S+)',1) ip, '源A' src FROM read_csv('文件A', ...)
  UNION ALL
  SELECT regexp_extract(line,'^(\S+)',1), '源B' FROM read_csv('文件B', ...)
) GROUP BY ip HAVING files >= 2 ORDER BY n DESC;
```
判定：**私网 IP 和账户名要结构性排除**（防张冠李戴——10.x/192.168.x 撞名是常态）;
跨源命中先看两边的时间是否咬合，时间对不上的「同实体」大概率是巧合。

## 三、Java 应用日志组（catalina/业务错误日志，多行堆栈）

> 2026-09-08 用 5.8G 真实入侵案日志验收沉淀。catalina 类日志没有 UA/IP 字段，
> access.log 模式天然不适用，攻击面在**应用行为异常**上。

```bash
rg -n -i \
  -e 'yv66vg' \                              # base64 Java 类魔数(CAFEBABE 头), 表达式注入载荷
  -e '\$\$Lambda\$' \                        # 动态加载类的 Lambda 痕迹
  -e 'org\.apache\.catalina\.filters\.[A-Z][a-z]{6,}' \  # 随机名 Filter(内存马典型)
  -e 'whoami|/bin/(ba)?sh|cmd\.exe|powershell' \         # 命令执行回显(见判定坑!)
  -e 'jndi|ldap://|rmi://|ceye\.io|oast\.(fun|me|live)|dnslog' \  # JNDI/OOB 回连
  -e 'loginFromDB|admin/admin123' \          # 内置账户爆破痕迹
  target.out
```

判定要点（全是实战坑）：
- **`cmd.exe` 类模式先排子串误报**：Java 包名 `*Cmd.execute`（如 AcquireJobsCmd.execute）
  会贡献百万级假命中——必须先 `rg -c 'Cmd\.execute'` 探一下，再用精确模式
  （`'cmd\.exe(\s|"|$)'` 或带命令参数的特征）；
- 随机名 Filter 判定：非 Tomcat 标准 Filter 名 + 首现时间与注入成功事件秒级咬合
  = 高优先候选（Filter 型内存马）；注册动作（addFilterDef）通常不留日志，
  只能从调用链侧面证实；
- 多行堆栈：以日期行（如 `dd-MMM-yyyy`）为切片锚点归组，**错误类型聚类优先于
  逐行签名**；堆栈续行占大头（实测 81%），只在可疑窗口内精读；
- JNDI/OOB 探测被拦截 ≠ 无事：出现探测 = 目标在对方清单上，同期要重点查
  有没有别的不被拦截的通道（如计划任务/脚本引擎）。

## 四、evtx 侧（hayabusa 之外的补充）

- hayabusa high/critical 全复核，med 抽样；
- **hayabusa 有盲区，手工纵切必须补位**（2026-09-08 实测：GPO 下发的伪装计划任务
  在 `-w` 全规则下零命中）。手工重点模式：
  - **根级任务名 vs 动作路径不匹配**：任务名叫 `\ChromeUpdate`/`\FoxUpdate` 这类
    仿浏览器更新，动作却指向 `C:\programdata\*.exe`（7z.exe/win.exe 等异常位置）——
    名实不符即候选；「运行一次即删、删后再注册」的循环模式加权；
  - **注册时机联动**：任务注册与 GPO 应用事件（SceCli 1704、Application 侧
    GroupPolicy 事件）秒级咬合 → 域级下发通道，问题在 DC 不在单机；
  - 手工重点事件 ID：4625(登录失败)突增 → 4624(成功)同账户；4698/4702(计划任务)；
    7045(新服务)；4720/4732(建账户/加组)；1102(日志清除——**先查是不是正常轮换**)；
    TaskScheduler Operational 106/200/141 与 Security 4698 双侧互证。

## 四、通用判定纪律

1. 每条候选写清：命中模式、证据位置（文件+行号）、为什么可疑、为什么不排除是噪音；
2. 拿不准的标「待复核」并写明需要用户补什么信息（这个 IP 是不是你们的扫描器？）；
3. 零命中也要写进报告：「按 X 模式扫了 Y 行，零命中」是有效结论，不是失败。
