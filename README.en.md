# claude-check

Claude account security scanner — self-check and anti-ban.

---

## Skills

### claude-ban-guard — Claude Account Security Scanner

Anthropic embedded steganographic marking in Claude Code (since v2.1.91): it detects 3 local signals (system timezone / `ANTHROPIC_BASE_URL` / relay domain) to identify mainland China users and flags them server-side for risk controls. A proxy alone won't help — the local signals must be cleared.

This Skill runs a read-only scan, producing a GREEN / YELLOW / RED verdict for each signal with fix steps.

**Trigger**: say "account security check" or `/claude-ban-guard`

Docs: [SKILL.md](claude-ban-guard/SKILL.md) · [Ban mechanism](claude-ban-guard/README.md)

---

## Installation

In any Agent that supports Skills:

```
Help me install this skill: https://github.com/tangheng418-netizen/claude-check/tree/main/claude-ban-guard
```

---

## License

[MIT](LICENSE)
