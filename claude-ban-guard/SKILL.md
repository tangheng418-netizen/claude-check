---
name: claude-ban-guard
description: >
  Claude 封号自检 + 防封修复。当用户说「会不会被封」「封号自检」「防封号」「检查我会不会被
  Anthropic 标记为中国用户」「查一下时区/中转站/BASE_URL 有没有暴露」「claude ban」「anti-ban」
  「隐写标记检查」「账号安全体检」时使用。只读扫描 Claude Code 用来给中国用户打隐写标记的 3 个信号
  (系统时区 / ANTHROPIC_BASE_URL / 中转站域名),逐项给 GREEN/YELLOW/RED 判定,再给一步步修复步骤;
  凡改环境变量 / .env / 系统时区 / BASE_URL 一律先讲清影响再问,绝不自动改。也用于账号被封后排查原因。
---

# claude-ban-guard —— Claude 封号自检与防封

## 这个 skill 干嘛的

Anthropic 在 Claude Code 里(自 2.1.91 / 2026-04-03 起)埋了**隐写术标记**:本地判断你是不是中国用户,是的话就在系统提示词 `Today's date is …` 中把单引号和日期分隔符换成肉眼看不出但机器能解码的 Unicode 变体,服务端据此对中国大陆请求做风控。3 个本地信号(不靠 IP):

1. **系统时区** —— Node 读到的 IANA 时区是否为 `Asia/Shanghai` / `Asia/Urumqi`
2. **`ANTHROPIC_BASE_URL`** —— 官方用户不设;设了非官方地址就是信号
3. **中转站域名** —— BASE_URL 域名与内置 147 中转站/大厂 + 11 AI 实验室关键词比对(base64+XOR 混淆)

同时扫描 **IP 信誉**(fraud score / IP 类型)、**网络环境一致性**(DNS/IPv6/WebRTC)、**Clash DNS 配置审计**、**浏览器加固**、**配置漂移检测**。

本 skill 只做两件事:**① 只读扫描;② 按处理归属表给修复步骤。**

## 铁律

- **扫描永远只读**,不碰任何文件、不设任何变量(唯一例外:配置快照写入 `~/.claude/claude-ban-guard-snapshot.json` 供漂移对比)
- 触碰**环境变量 / `.env` / 系统时区 / `ANTHROPIC_BASE_URL` / 系统配置**属于红线:**先说清「改什么+改了会怎样+风险」再问,拿到明确同意才动。绝不自动改。**
- 诚实:这些手段只能**降低被标记概率**,不保证不封;中国大陆不属 Anthropic 支持区,用中转违反 ToS。

## 第 1 步:跑只读自检

```powershell
powershell -NoProfile -File "<skill 目录>/scan.ps1" -ProjectDir "<项目根>"
# 可选跳过网络相关检查:
#   -SkipReputation  跳过 IP 信誉查询
#   -SkipClashAudit  跳过 Clash DNS 配置审计
```

## 第 2 步:按固定模板输出报告

### 处理归属表(唯一标准,别临场改判)

| # | 检查项 | 不通过时怎么处理 | 谁处理 |
|---|---|---|---|
| ① | 系统时区 | 在启动 Claude 的环境设 `TZ=非中国时区`,不动 Windows 系统时区。长期生效可加用户环境变量 | 🤖 Claude 可代做(需确认) |
| ② | `ANTHROPIC_BASE_URL` | 清空三处(env/`settings.json`/`.env`)直连官方;必须中转则换独立自建域名;或用官方 CLI 订阅登录天然规避 | ✋ 手动(只给指引) |
| ③ | 中转站域名 | 同 ② | ✋ 手动 |
| ④ | IP 信誉(fraud score/IP 类型) | 欺诈分≥30 或 hosting/datacenter IP → 换 residential/ISP 原生节点。自测:scamalytics.com 输 IP 看 fraud score | ✋ 手动(换节点) |
| ⑤ | 网络环境一致性 | 对齐出口 IP 国家/DNS/时区/语言;关 IPv6(网卡属性);WebRTC→browserleaks.com/webrtc;DNS→dnsleaktest.com;IPv6→test-ipv6.com | ✋ 手动(代理/系统设置) |
| ⑥ | 浏览器加固 | Chrome 加 `--lang=en-US --force-webrtc-ip-handling-policy=disable_non_proxied_udp`;设置英语为首选语言;关定位;关 IPv6 | ✋ 手动(浏览器/系统设置) |
| ⑦ | Clash DNS 配置 | 改 DNS 覆写:nameserver 换 8.8.8.8/Cloudflare;删 doh.pub/dns.alidns.com/223.x;关 IPv6 DNS 解析 | ✋ 手动(Clash 设置) |
| ⑧ | DeepSeek 兜底 | `.env` 补 `DEEPSEEK_API_KEY` | ✋ 手动(.env 是红线) |

### 报告模板

```
# Claude / Codex 账号安全自查报告

- 自查时间：<time>
- 适用范围：Claude Code（隐写标记已确证）。Codex 等本地 AI 工具目前无同类曝光，但系统时区/代理地址逻辑通用。
- Claude Code 版本：<ver>（隐写逻辑自 2.1.91 起存在，版本新≠安全，看信号）

## 一、本次查了哪些内容
1. 系统时区信号 —— Node 读本地 IANA 时区判是否中国大陆（挂代理绕不过）
2. ANTHROPIC_BASE_URL 信号 —— 官方用户不设它；设了非官方地址即被标记（查环境变量/settings.json/.env 三处）
3. IP 信誉 —— fraud score + IP 类型(isp/hosting/business) + 是否 datacenter/代理/VPN
4. 网络环境一致性 —— 出口 IP 国家/DNS/IPv6/WebRTC/时区/语言交叉比对（与隐写标记是两条独立判定线）
5. 浏览器加固 —— best-effort 读浏览器语言+加固启动参数（仅浏览器登录/管账号时相关）
6. Clash DNS 配置审计 —— 扫描 Clash YAML 中 nameserver 是否含中国 DNS（fake-ip 下不泄露但属回退风险）
7. 配置漂移检测 —— 与上次快照对比，发现 Clash 升级/重置等导致的配置回退
8. Claude Code 版本 + DeepSeek 兜底

## 二、查询结果
| # | 检查项 | 实测 | 结果 |
|---|---|---|---|
| 1 | 系统时区 | <iana / TZ env> | <✅ / ❌> |
| 2 | ANTHROPIC_BASE_URL | <值或「未设」> | <✅ / ❌> |
| 3 | IP 信誉 | <fraud score / IP type> | <✅ / ⚠️ / ❌> |
| 4 | 网络环境一致性 | <出口 IP 国家 / 时区 / 语言 / DNS> | <✅ / ⚠️ / ❌> |
| 5 | 浏览器加固 | <语言 / WebRTC 启动参数> | <✅ / ⚠️ / 跳过> |
| 6 | Clash DNS 配置 | <是否含中国 DNS> | <✅ / ⚠️ / 跳过> |
| 7 | 配置漂移 | <无漂移 / 检测到变化> | <✅ / ⚠️> |
| 8 | DeepSeek 兜底 | <已配置 / 未配置> | <✅ / ⚠️> |

总体结论：<✅ 全部通过 / ❌ 或 ⚠️ 存在风险项，见第三节>

## 三、存在风险项 → 怎么处理 + 谁来处理
（逐项展开第二节中所有非 ✅ 的项——❌ 和 ⚠️ 一视同仁——严格按处理归属表输出。⚠️ 项也必须给处理步骤，不能丢进第四节。）
- ❌/⚠️ <检查项>：<现象与风险> → <具体处理步骤+自测工具/网址> → 处理方：<🤖/✋>
- （示例）⚠️ 网络环境一致性：出口 IP=US 但时区=Asia/Shanghai、语言=zh-CN → 矛盾信号判为可疑。处理：对齐时区(设 TZ)、语言改 en-US、关 IPv6(网卡属性)。浏览器自测：①WebRTC→browserleaks.com/webrtc ②DNS→dnsleaktest.com ③IPv6→test-ipv6.com。仅命令行用 Claude 不受 WebRTC 影响 → ✋ 需你手动

## 四、提醒
- 标记只是识别，封号还看行为：别单账号超大量调用，别多账号共用一个出口 IP。
- 封号邮件里另埋了地址追踪器(本 skill 查不到)：关掉邮件客户端远程图片自动加载。
- 这是概率对抗，不保证不封。**Claude Code 升级后/改连接方式后/代理客户端更新后请重跑本自查。**
```

## 第 3 步:解释扫描结果的关键点

### 为什么扫描显示 X 但实测是 Y？

| 扫描显示 | 可能原因 | 自测方法 |
|---|---|---|
| IPv6: present | 虚拟网卡(vgate0/Radmin/WSL)残影,非物理链路 | test-ipv6.com |
| DNS: 中国 IP | 网卡 DHCP 分配的 DNS ≠ Clash fake-ip 实际走的 | dnsleaktest.com |
| TZ env: (not set) | PowerShell 进程未继承用户环境变量(需注销重登) | `node -e "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)"` |

### 时区修复(Claude Desktop 专用)

Claude Desktop 是 Electron 图形 App,不通过终端启动。设 `TZ` 必须走**用户级环境变量**才能让它读到:
- 设置→系统→关于→高级系统设置→环境变量→用户变量→新建:`TZ`=`America/Los_Angeles`
- **必须注销重登**才能让新进程继承
- 验证:终端跑上面的 node 命令
- 副作用:所有读本地时区的程序都会看到新时区(日志时间戳等),确认时区敏感逻辑用的是显式时区

### IP 信誉解读

- **fraud score 0-100**:ipapi.is 的 abuser_score×100。<10=干净, ≥30=需关注, ≥80=高风险
- **IP type**:`isp`=住宅(最优), `business`=企业(尚可), `hosting`=数据中心(最可疑——风控引擎重点审查)
- **scamalytics 交叉验证**:浏览器打开 `scamalytics.com/ip/<你的IP>` 看 Fraud Score

## 收尾

- 严格按第 2 步模板输出报告,不要另起格式
- 报告末尾把待办按「🤖 Claude 可代做(需确认)/ ✋ 需你手动」分类列清
