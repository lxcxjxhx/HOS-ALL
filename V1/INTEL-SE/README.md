# AI Attack Simulator (C)

A system for automated penetration testing with a GTK-based GUI for configuring AI models (DeepSeek, Ollama, Claude 3.7, Gemini, Grok, IronHeart).

## Setup
1. Install dependencies: `sudo apt-get install libgtk-4-dev libcurl4-openssl-dev libyaml-dev libcjson-dev`
2. For Ollama: Ensure Ollama is running locally with a model (e.g., LLaMA).
3. For DeepSeek, Claude, Gemini, Grok: Add API keys to `config/settings.yaml`.
4. For IronHeart: Add the special endpoint URL to `config/settings.yaml`.
5. Configure targets in `config/sites.yaml`.
6. Build: `make`
7. Run: `./ai_attack_simulator`
8. Test: `make test`

## GUI Usage
- Select an AI model from the dropdown.
- View configuration instructions for the selected model.
- Enter API keys or endpoint URLs as required.
- Click "Save Configuration" to update `settings.yaml`.
- Click "Run Attack" to execute attacks and view results.
