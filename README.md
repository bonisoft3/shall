# shall

AI-powered command approval gate for Claude Code. Classifies shell commands as **allow**, **deny**, or **ask** before execution.

## How it works

shall runs as a Claude Code `PreToolUse` hook. Every Bash command is sent to an AI model which classifies it:

- **allow** — normal development commands pass through silently
- **deny** — dangerous commands are blocked (surfaced as "ask" so the human decides)
- **ask** — ambiguous commands or merge operations prompt the user for approval

Default provider: **Gemini 2.5 Flash Lite** (fast, no battery drain). Falls back to **Ollama** (local, offline-capable) if Gemini is unavailable.

## Install

### 1. Install nushell

**macOS**
```bash
brew install nushell
```

**Linux**
```bash
brew install nushell
# or: https://www.nushell.sh/book/installation.html
```

**Windows**
```powershell
winget install Nushell.Nushell
```

### 2. Set your Gemini API key

```bash
export GEMINI_API_KEY=your-key-here  # add to ~/.bashrc or ~/.zshrc
```

Get a free key at [aistudio.google.com](https://aistudio.google.com/apikey).

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

### Optional: Ollama fallback

For offline use, install Ollama as a fallback:

```bash
brew install ollama
ollama pull qwen2.5-coder:7b
```

shall auto-falls back to Ollama when Gemini is unavailable (no API key, quota exhausted, network down).

## Model accuracy

Tested with 31 commands (23 allow, 1 ask, 7 deny):

| Model | Score | Avg latency | Provider |
|-------|-------|-------------|----------|
| `gemini-2.5-flash-lite` | 31/31 | ~630ms | Gemini (default) |
| `gemini-2.5-flash` | 31/31 | ~1.9s | Gemini |
| `qwen2.5-coder:7b` | 31/31 | ~19.7s | Ollama |
| `gemma3:1b` | 29/31 | ~11.5s | Ollama |
| `qwen2.5-coder:3b` | 28/31 | ~13.6s | Ollama |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SHALL_PROVIDER` | `gemini` | Provider: `gemini` or `ollama` |
| `SHALL_FALLBACK` | `true` | Fall back to ollama if gemini fails |
| `GEMINI_API_KEY` | — | Google AI API key (required for gemini) |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model ID |
| `GEMINI_URL` | `https://generativelanguage.googleapis.com/v1beta` | Gemini API base URL |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Ollama model for classification |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |

### Tuning the prompt

If a command is consistently misclassified, add it as a few-shot example in the `gate_prompt` function in `shall.nu`. Small models are very sensitive to examples — a single added example often fixes an entire class of misclassifications.

## Development

```bash
# Install dev tools
mise install

# Syntax check
sayt build

# Run tests (default: gemini)
sayt test   # or: nu shall.test.nu

# Test ollama provider
nu shall.test.nu --provider ollama

# Test a different model
nu shall.test.nu --provider ollama --model qwen2.5-coder:3b

# Prompt optimization (multi-model comparison)
sayt verify   # runs promptfoo eval

# Integration tests (Docker, ollama only)
docker compose run --build integrate
```
