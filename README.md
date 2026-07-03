# AI Starter Kit

AI 入门实战工具集，从账号安全到效率提升，新手开箱即用。

---

## Skills

### claude-ban-guard —— Claude 封号自检与防封

Anthropic 在 Claude Code 中（自 2.1.91 起）埋了隐写术标记：通过系统时区 / `ANTHROPIC_BASE_URL` / 中转站域名 3 个本地信号识别中国大陆用户，服务端据此风控封号。即使挂海外代理，本地信号不清照样被打标记。

本 Skill 跑只读扫描，逐项给出 GREEN / YELLOW / RED 判定和修复步骤。

**触发**：说「封号自检」「账号安全体检」或 `/claude-ban-guard`

详细文档：[SKILL.md](claude-ban-guard/SKILL.md) · [封号机制](claude-ban-guard/README.md)

---

## 安装

在支持 Skill 的 Agent 里说：

```
帮我安装这个 skill：https://github.com/tangheng418-netizen/ai-starter-kit/tree/main/claude-ban-guard
```

---

## License

[MIT](LICENSE)
