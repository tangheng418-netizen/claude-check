# claude-ban-guard —— Claude 封号自检与防封

> Anthropic 在 Claude Code 里埋了**隐写术标记**自 2.1.91 起:靠系统时区 / `ANTHROPIC_BASE_URL` / 中转站域名 3 个本地信号识别中国用户,服务端据此风控封号。即使挂海外代理,本地信号不清照样被打标记。

## 扫描内容

| 信号 | 说明 |
|---|---|
| 系统时区 | Node IANA 时区是否 = Asia/Shanghai 或 Asia/Urumqi |
| ANTHROPIC_BASE_URL | 三处(env / settings.json / .env)是否设了非官方地址 |
| IP 信誉 | fraud score + IP 类型(isp/hosting/business) + datacenter 检测 |
| 网络一致性 | 出口 IP 国家 vs DNS/IPv6/WebRTC/时区/语言交叉比对 |
| 浏览器加固 | Chrome/Edge 语言 + WebRTC 启动参数检测 |
| Clash DNS 审计 | Clash YAML 中 nameserver 是否含中国 DNS |
| 配置漂移 | 与上次快照对比,检测 Clash 升级等导致的配置回退 |

## 使用

在支持 SKILL.md 的 Agent 平台中说「封号自检」或 `/claude-ban-guard` 即可触发。

手动跑:

```powershell
powershell -NoProfile -File "scan.ps1" -ProjectDir "<项目根>"
```

详细文档见 [SKILL.md](SKILL.md)。
