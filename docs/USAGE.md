# Usage Reference

## Commands

### `llmguard scan`

Run a security scan against an LLM target.

```bash
llmguard scan --target <provider> [OPTIONS]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Provider name (`openai`, `anthropic`, `ollama`) | Required |
| `--model` | Specific model (e.g., `gpt-4`, `gpt-3.5-turbo`) | Provider default |
| `--api-key` | API key (overrides env/config) | From env/config |
| `--system-prompt` | System prompt string | None |
| `--system-prompt-file` | Path to system prompt file | None |
| `--budget` | Maximum spend in USD | `1.0` |
| `--output` | Save JSON report to file | None |
| `--ci` | CI mode: exit code reflects risk level | `false` |
| `--quick` | Quick mode: only high-confidence attacks | `false` |
| `--attacks` | Comma-separated attack IDs to run | All attacks |

**Examples:**

```bash
# Basic scan with default budget
llmguard scan --target openai

# Scan specific model with custom budget
llmguard scan --target openai --model gpt-4 --budget 0.50

# Scan with system prompt
llmguard scan --target openai --system-prompt "You are a helpful assistant."
llmguard scan --target openai --system-prompt-file ./prompt.txt

# Quick scan (high-confidence attacks only)
llmguard scan --target openai --quick

# Run specific attacks
llmguard scan --target openai --attacks direct_injection,docx_hidden_text

# CI mode with JSON output
llmguard scan --target openai --ci --output report.json
```

**CI Exit Codes:**

| Code | Meaning |
|------|---------|
| `0`  | No vulnerabilities found (risk score = 0) |
| `1`  | Vulnerabilities found (risk score > 0) |
| `2`  | Critical risk (risk score >= 80) |

### `llmguard demo`

Run a demonstration scan with pre-recorded results. No API key needed.

```bash
llmguard demo
```

### `llmguard list`

List all available attack modules.

```bash
llmguard list
```

Shows a table with attack name, category, test case count, and description.

### `llmguard info`

Show tool version, attack counts, and configuration status.

```bash
llmguard info
```

## Report Formats

### Terminal Output

Rich terminal output with colored severity indicators, progress bars, and summary tables. Shown by default for all commands.

### JSON Report

```bash
llmguard scan --target openai --output report.json
```

JSON structure:
```json
{
  "target": "openai-gpt-3.5-turbo",
  "model": "gpt-3.5-turbo",
  "timestamp": "2025-01-01T00:00:00Z",
  "budget_limit": 1.0,
  "vulnerabilities": [...],
  "all_results": [...],
  "summary": {
    "total_attacks_run": 15,
    "total_vulnerabilities": 4,
    "by_severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1},
    "risk_score": 45,
    "recommendation": "MEDIUM RISK: Review and mitigate findings.",
    "total_cost": 0.037,
    "budget_status": {...}
  }
}
```

### HTML Report

```bash
llmguard scan --target openai --output report.html
```

Self-contained HTML file with dark theme, inline styles, no external dependencies. Can be shared or hosted.

## Budget Management

LLMGuard tracks API costs in real-time. If the budget is exceeded mid-scan, remaining attacks are skipped and the report notes incomplete results.

```bash
# Set budget to $0.50
llmguard scan --target openai --budget 0.50
```

Typical scan costs:
- **Quick mode**: ~$0.02-$0.05
- **Full scan (GPT-3.5)**: ~$0.05-$0.20
- **Full scan (GPT-4)**: ~$0.20-$1.00
