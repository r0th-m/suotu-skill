# 工具使用卡（索图外勤）

> 每张卡：用途 / 获取 / 实测命令 / 输出格式 / 坑。
> Windows 卡 2026-08-19 在本机（Win11, Git Bash + cmd）实测；Linux 卡为同版本
> 官方工具的 bash 方言等价写法（**未在 Linux 实测**，标注出的差异点以官方文档为准）。
> 哈希值以官方 release 页为准，下载后必须 `sha256sum` / `certutil -hashfile` 比对。

---

## 1. ripgrep（rg）——纵切主力，签名扫描

- 用途：GB 级日志的多模式检索/计数/抽行，全内存映射，极快。
- 获取：https://github.com/BurntSushi/ripgrep/releases （实测版本 15.1.0）
  - Windows: `ripgrep-<ver>-x86_64-pc-windows-msvc.zip`；Linux: `-x86_64-unknown-linux-musl.tar.gz`
- 实测性能：1.2GB / 1000 万行，五模式扫描 0.5 秒。

**多模式扫描（命中行+行号）：**
```bash
# bash / Git Bash
rg -n -i -e 'union(\s|\+|%20)select' -e '\.\./' -e '/etc/passwd' -e 'sqlmap|nikto' access.log
```
```powershell
# PowerShell 注意: -e 后面的模式用单引号; % 无需转义, 但 $ 触发变量展开要留意
rg -n -i -e 'union(\s|\+|%20)select' -e '\.\./' access.log
```

**只计数不出行（大结果集先探量）：**
```bash
rg -c -i 'sqlmap' access.log        # 每文件命中行数
rg --stats -i 'union select' access.log   # --stats 打搜索统计
```

**坑：**
- `rg -c ''` 可以数总行数（空模式匹配每行）；
- Windows 下输出中文/UTF-8 日志无问题，但 cmd 直接输出可能乱码——重定向到文件再看；
- 模式含 `'` 时用双引号包模式（bash 反之）——写命令前先想 shell 方言；
- 递归目录：`rg -n pattern <目录>`；zgrep 类需求：`rg -z` 直接吃 .gz。

---

## 2. duckdb（CLI）——统计聚合/临时检索层

- 用途：把日志当表查：分组计数、时间窗口、TopN、方差。大日志的「统计基线」靠它。
- 获取：https://github.com/duckdb/duckdb/releases （实测 1.5.5）
  - Windows: `duckdb_cli-windows-amd64.zip`；Linux: `duckdb_cli-linux-amd64.zip`
- 实测性能：1.2GB / 1000 万行聚合 ≈9 秒（冷读），热缓存亚秒。

**行模式读取（关键惯用法，别用 read_text）：**
```sql
-- read_text 会把整个文件读成一行 blob, 不能用于逐行分析!
-- 行模式的正确姿势: 用不可能出现的分隔符 \x01 把每行读成一个字段
SELECT line FROM read_csv('路径/access.log',
       header=false, delim='\x01', quote='', columns={'line':'VARCHAR'});
```

**访问日志状态码分布：**
```sql
SELECT regexp_extract(line, '"\s(\d{3})\s', 1) AS status, count(*) AS n
FROM read_csv('E:/logs/access.log', header=false, delim='\x01', quote='',
              columns={'line':'VARCHAR'})
GROUP BY 1 ORDER BY n DESC;
```

**Top IP：**
```sql
SELECT regexp_extract(line, '^(\S+)', 1) AS ip, count(*) AS n
FROM read_csv(...) GROUP BY 1 ORDER BY n DESC LIMIT 20;
```

**按分钟速率（突刺检测的数据源）：**
```sql
SELECT date_trunc('minute',
         strptime(regexp_extract(line, '\[([^\]]+)\]', 1),
                  '%d/%b/%Y:%H:%M:%S %z')) AS minute, count(*) AS n
FROM read_csv(...) GROUP BY 1 ORDER BY 1;
```

**坑：**
- **取时间范围必须先 strptime 再 min/max**——`regexp_extract` 出的 `dd/Mon/yyyy`
  是字符串，字典序 min/max 会给出错误首尾（2026-09-08 回归实测：字典序得出
  01/Apr~31/Oct，真实跨度 15 个月全丢）。正确：`min(strptime(ts,'%d/%b/%Y:%H:%M:%S %z'))`；
- **`.read` 的参数路径必须是 Windows 形式**（`C:\...`）——SQL 字符串里可以
  用正斜杠，但 `.read` 的参数不认 MSYS 的 `/c/...`（报 cannot open）；
- `.echo on` 会把 SQL 原文混进 `.output` 的 CSV 头部——机读输出别开 `.echo on`；
- Windows 路径在 SQL 字符串里用正斜杠（`E:/logs/...`），反斜杠会被转义规则吃掉；
- **CRLF/LF 混合文件：duckdb 行级聚合不可用**（2026-09-08 5.8G 实测）——
  真实 catalina.out（469 万行 CRLF 混在 LF 里）即使三参数齐上，
  read_csv 既虚增数百万 NULL 行又丢十几万实行，且 `ignore_errors=true` 下
  无任何报错。**对账纪律（duckdb 行数 vs `rg -c ''`）是唯一能逮住它的闸**：
  对不上 = 判定 duckdb 不适合该文件，行级统计全部回退 rg 管道
  （rg 计数/聚合正则组 + GNU awk 汇总），duckdb 仅用于能自证一致的场景；
- **真实日志喂 read_csv 必须三参数齐上**：
  `max_line_size=10000000, ignore_errors=true, strict_mode=false`——
  2026-09-08 验收实测：只加前两个会**静默丢弃含 `\xNN` 转义文本的行**
  （恰是 TLS 探测/恶意负载行，93880 行丢了 315 行），加 `strict_mode=false`
  才与 `rg -c ''` 行数对账一致。**行数对账是强制步骤**：
  duckdb count ≠ rg 行数 = 有丢行，停下来查，不许带着缺口继续；
- **正则匹配用 `regexp_matches(line,'pat')`，别用 `line ~ 'pat'`**——
  1.5.5 实测 `~` 对部分数据返回 0 行而 regexp_matches 返回正确结果；
- duckdb 批处理输出**不要接 `head`**（SIGPIPE 会杀掉 duckdb 进程，
  SQL 文件后半段静默不执行）——要看头部用 SQL 的 `LIMIT`；
- 官方 release **不发布 SHA256 校验和文件**（实测 404）——校验纪律降级为：
  只用官方 releases 页链接 + 钉死版本号（卡片里写的就是实测版本）；
- `strptime` 的时区格式符 `%z` 吃 `+0800`；格式不匹配返回 NULL 不报错——先 LIMIT 10 验证再全量；
- 结果 NULL 行会混入 GROUP BY，过滤条件里记得 `WHERE ip <> ''`；
- Linux 下同 SQL 不变，仅路径写法不同。

---

## 3. evtx_dump —— Windows 事件日志解析

- 用途：.evtx → XML/JSONL，喂给 rg/jq。
- 获取：https://github.com/omerbenamram/evtx/releases （实测 0.12.1）
  - Windows: `evtx_dump-vX.Y.Z.exe`；Linux 有对应二进制。

**转 JSONL（推荐，后续可 jq）：**
```bash
# bash / Git Bash(Windows 二进制同样用法)
evtx_dump -o jsonl --no-confirm-overwrite -f work/security.jsonl Security.evtx
```
**转 stdout 直接进管道：**
```bash
evtx_dump -o jsonl Security.evtx | jq -c 'select(.Event.System.EventID["#text"]=="4625")'
```

**输出格式（jsonl 每行一个事件，XML 转 JSON 的结构坑）：**
- 事件 ID 的取法不固定：元素带属性时是 `{"#text": "4625", ...}`、不带属性时是裸数字——
  jq 统一用 `(.Event.System.EventID | if type=="object" then .["#text"] else . end)`
  （2026-09-08 实测同一字段两种形态都存在，卡片旧写法遇到裸数字直接报类型错）；
- 时间在 `.Event.System.TimeCreated["#attributes"].SystemTime`；
- **EventData 是直接命名对象，不是 XML 式 `Data[]` 数组**：
  用 `.Event.EventData.NewProcessName`、`.Event.EventData.TargetUserName` 直接取
  （按 `Data[]` 数组写 filter 不报错但静默全空——2026-09-08 回归实测坑）；
  个别字段值仍可能是 `{"#text": ...}` 形态，同样用 if type 分支兜底。

**坑：** 输出到已有文件会问确认，自动化必须加 `--no-confirm-overwrite`。

---

## 4. jq —— JSON 瑞士刀

- 用途：evtx_dump JSONL、业务系统 JSON 日志的过滤/整形。
- 获取：https://github.com/jqlang/jq/releases （实测 1.8.2）
  - Windows: `jq-windows-amd64.exe`；Linux: `jq-linux-amd64`

**过滤特定事件 ID（接 evtx_dump）：**
```bash
jq -c 'select(.Event.System.EventID["#text"]=="4625") |
       {t: .Event.System.TimeCreated["#attributes"].SystemTime}' work/security.jsonl
```
**逐字段提取成表格行：**
```bash
jq -r '[.Event.System.EventID["#text"], .Event.System.Computer] | @tsv' work/security.jsonl
```

**坑：**
- Windows 的 jq.exe 在 cmd/PowerShell 里引号规则不同：PowerShell 用单引号包 filter 最安全；
- **过滤器含反斜杠（Windows 路径/计划任务名 `\Chrome` 等）时，Git Bash 双引号内
  内联 jq 转义极易出错**——过滤器写进文件用 `jq -f filter.jq`（2026-09-08 连踩三次后
  的可靠姿势）；
- **Windows 上 jq 接 `head` 会报 `writing output failed: Invalid argument`**
  （类 SIGPIPE）——结果其实已写全，无害噪音，别被吓到去返工；
- `-c` 紧凑输出（一行一条）适合管道，`-r` 去引号适合文本；
- 报错信息里的 `<stdin>:N` 是行号，排查坏行直接跳该行。

---

## 5. hayabusa —— Windows 事件日志检测引擎（Sigma 规则库）

- 用途：evtx 目录一键跑几千条 Sigma 规则，出分级时间线。**它代替你精读**，你只复核它的 high/critical。
- 获取：https://github.com/Yamato-Security/hayabusa/releases （实测 4.0.0）
  - Windows: `hayabusa-<ver>-win-x64.zip`；Linux: `hayabusa-<ver>-linux-x64-musl.zip`（或 gnu 版）
- 实测性能：整个案件 evtx 目录（数十个文件）4 秒。

**一键时间线：**
```bash
# v4.0.0 起子命令叫 dfir-timeline（旧版叫 csv-timeline, 网上老教程全是旧名, 别照抄）
hayabusa dfir-timeline -d <evtx目录> -o work\timeline.csv -q -w   # Windows
hayabusa dfir-timeline -d <evtx目录> -o work/timeline.csv -q -w   # Linux 同, 仅路径分隔符差异
```
**只看高危（读 CSV 而不是重扫）：**
```bash
# CSV 第 3 列是级别(info/low/med/high/critical)
rg -n ',high,|,critical,' work/timeline.csv
```

**坑：**
- 子命令版本差异大（csv-timeline→dfir-timeline），`hayabusa help` 先看一眼再动手；
- **时间线默认按本地时区渲染**（如 +08:00）——显式加 **`-U`（`--utc`）输出 UTC**，
  报告统一用 UTC 表述（4.0.0 的 dfir-timeline 只有 `-U/--utc` 和 `-O/--iso-8601`，
  **没有 `-T/--timezone`**，旧卡片写错过，2026-09-08 回归实锤）；
- **CSV 级别字段带引号**：提取高危要用 `,"high",|,"critical",`（带引号），
  写 `,high,` 会零命中；
- `-w` 是启用所有规则（含 noisy）；`-q` 静默；规则库内置在 zip 里，离线可用；
- 结果是**候选不是结论**，尤其 med/low 误报多——只拿 high/critical 进精读，med 抽样看。

---

## 无工具手工路径（全部降级时）

只有 OS 自带工具时的保命姿势（**浅层、抽样级，报告里必须如实标注**）：
- Windows PowerShell：`Get-Content x.log -TotalCount 500`（抽样）、
  `Select-String -Path x.log -Pattern 'sqlmap' | Select -First 200`（签名）；
- Linux bash：`head -500`、`grep -nEi 'pattern' x.log | head -200`、`wc -l`；
- 大文件不整体读入上下文，分段抽样（头/中/尾各一段）；
- evtx 无工具时：**不要尝试手解二进制**，直接告知「evtx 需要 evtx_dump 或回索图」。
