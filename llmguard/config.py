import os
import sys
from pathlib import Path
from typing import Optional
import yaml


class Config:
    """
    Multi-provider API key management (BYOK model).

    Priority order:
    1. Environment variable (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
    2. Config file (~/.llmguard/config.yml)
    3. Interactive prompt (if terminal and required=True)
    4. Return None (if required=False, for demo mode)
    """

    @classmethod
    def get_api_key(cls, provider: str, required: bool = True) -> Optional[str]:
        """
        Get API key for the specified provider.

        Args:
            provider: Provider name ("openai", "anthropic", "ollama")
            required: If False, return None instead of raising error (for demo mode)

        Returns:
            API key string, or None if not required and not found

        Raises:
            ValueError: If required=True and key not found
        """
        # Map provider to environment variable name
        env_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "ollama": "OLLAMA_HOST"  # Optional, defaults to localhost
        }

        env_key = env_map.get(provider)
        if not env_key and required:
            raise ValueError(f"Unknown provider: {provider}")

        # 1. Check environment variable
        if env_key and (key := os.getenv(env_key)):
            return key

        # 2. Check config file
        if key := cls._load_from_config(provider):
            return key

        # 3. Interactive prompt (only if required)
        if required and sys.stdout.isatty():
            return cls._interactive_prompt(provider)

        # 4. Not required (demo mode)
        if not required:
            return None

        # Required but not found - raise error
        raise ValueError(
            f"No API key found for {provider}.\n"
            f"Set: export {env_key}=your-key\n"
            f"Or create: ~/.llmguard/config.yml\n"
            f"Or run in demo mode: llmguard demo"
        )

    @classmethod
    def _load_from_config(cls, provider: str) -> Optional[str]:
        config_path = Path.home() / ".llmguard" / "config.yml"
        if not config_path.exists():
            return None
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
        return config.get(provider.lower())

    @classmethod
    def _interactive_prompt(cls, provider: str) -> str:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel.fit(
            f"[yellow]No API key found for {provider}[/yellow]\n\n"
            f"Set: export {provider.upper()}_KEY=your-key",
            title="API Key Required",
            border_style="yellow"
        ))
        key = input(f"\n{provider} API key: ").strip()
        if not key:
            raise ValueError("API key cannot be empty")
        save = input("Save to config file? (y/N): ").lower()
        if save == 'y':
            cls._save_key(provider, key)
        return key

    @classmethod
    def _save_key(cls, provider: str, key: str):
        config_dir = Path.home() / ".llmguard"
        config_dir.mkdir(exist_ok=True, mode=0o700)
        config_file = config_dir / "config.yml"
        config = {}
        if config_file.exists():
            with open(config_file) as f:
                config = yaml.safe_load(f) or {}
        config[provider.lower()] = key
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        config_file.chmod(0o600)
