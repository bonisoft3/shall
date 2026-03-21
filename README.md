# shall

AI-powered command approval gate for Claude Code. Uses a local Ollama model to classify shell commands as **allow**, **deny**, or **ask** before execution.

## How it works

shall runs as a Claude Code `PreToolUse` hook. Every Bash command is sent to a local Ollama model (default: `qwen2.5-coder:7b`) which classifies it:

- **allow** — normal development commands pass through silently
- **deny** — dangerous commands are blocked
- **ask** — ambiguous commands prompt the user for approval

## Install

### 1. Install dependencies

**macOS**
```bash
brew install nushell ollama
```

**Linux**
```bash
# Nushell
brew install nushell
# or: https://www.nushell.sh/book/installation.html

# Ollama
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows**
```powershell
winget install Nushell.Nushell Ollama.Ollama
```

### 2. Pull the model and start Ollama

```bash
ollama pull qwen2.5-coder:7b
ollama serve  # leave running, or it auto-starts on macOS
```

### 3. Install the hook

```bash
mkdir -p ~/.claude/hooks
curl -o ~/.claude/hooks/shall.nu \
  https://raw.githubusercontent.com/bonisoft3/shall/main/shall.nu
```

### 4. Register in Claude Code

Add to `~/.claude/settings.json` (create the file if it doesn't exist):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "nu ~/.claude/hooks/shall.nu"
          }
        ]
      }
    ]
  }
}
```

That's it. Claude Code will now evaluate every Bash command through the gate.

## Model accuracy

Tested with 19 commands (12 allow, 7 deny):

| Model | Score | Avg latency | Recommended |
|-------|-------|-------------|-------------|
| `qwen2.5-coder:7b` | 19/19 | ~3-5s | Yes |
| `qwen2.5-coder:3b` | 18/19 | ~1.7s | If speed matters |
| `gemma3:1b` | 17/19 | ~1s | No |
| `gemma3:4b` | 16/19 | ~2-3s | No |

## Configuration

Edit constants at the top of `shall.nu`:

| Constant | Default | Description |
|----------|---------|-------------|
| `MODEL` | `qwen2.5-coder:7b` | Ollama model for classification |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `TIMEOUT` | `15sec` | Max wait for model response |

Override the endpoint via environment variable:

```bash
export OLLAMA_URL=http://my-gpu-server:11434
```

### Tuning the prompt

If a command is consistently misclassified, add it as a few-shot example in the `gate_prompt` function in `shall.nu`. Small models are very sensitive to examples — a single added example often fixes an entire class of misclassifications.

## Development

```bash
# Install dev tools
mise install

# Syntax check
sayt build

# Run tests (requires ollama serve)
sayt test   # or: nu shall.test.nu

# Test a different model
nu shall.test.nu --model qwen2.5-coder:3b

# Prompt optimization (multi-model comparison)
sayt verify   # runs promptfoo eval

# Integration tests (Docker)
docker compose run --build integrate
```
