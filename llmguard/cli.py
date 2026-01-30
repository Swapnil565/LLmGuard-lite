"""
LLMGuard-Lite CLI interface.

Commands:
    llmguard scan     - Run security scan against an LLM target
    llmguard demo     - Show demo results (no API key needed)
    llmguard list     - List all available attacks
    llmguard info     - Show details about a specific attack
"""
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from llmguard import __version__


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="llmguard")
def cli():
    """LLMGuard-Lite: Security scanner for LLM applications."""
    pass


@cli.command()
@click.option("--target", type=click.Choice(["openai"]), required=True, help="LLM provider to scan")
@click.option("--model", default="gpt-3.5-turbo", help="Model name (default: gpt-3.5-turbo)")
@click.option("--system-prompt", default=None, help="System prompt string")
@click.option("--system-prompt-file", default=None, type=click.Path(exists=True), help="Path to system prompt file")
@click.option("--budget", default=1.0, type=float, help="Max budget in USD (default: 1.0)")
@click.option("--output", default="report.json", help="Output file path (default: report.json)")
@click.option("--ci", is_flag=True, help="CI mode: JSON to stdout, no colors, no progress bar")
@click.option("--quick", is_flag=True, help="Quick mode: only run high-success-rate attacks")
@click.option("--attacks", default=None, help="Comma-separated list of attack IDs to run")
@click.option("--api-key", default=None, help="API key (or set via env var)")
def scan(target, model, system_prompt, system_prompt_file, budget, output, ci, quick, attacks, api_key):
    """Run a security scan against an LLM target."""
    from llmguard.config import Config
    from llmguard.targets.openai import OpenAITarget
    from llmguard.scanner import LLMGuardScanner
    from llmguard.scoring.reporter import Reporter

    # Resolve system prompt
    if system_prompt_file:
        with open(system_prompt_file, "r", encoding="utf-8") as f:
            system_prompt = f.read().strip()

    # Resolve API key
    if not api_key:
        api_key = Config.get_api_key(target)

    # Print header
    if not ci:
        console.print(Panel(
            f"[bold cyan]LLMGuard Security Scanner v{__version__}[/bold cyan]\n"
            f"Target: {target}-{model}  |  Budget: ${budget:.2f}",
            border_style="cyan"
        ))

    # Create target
    try:
        llm_target = OpenAITarget(api_key=api_key, model=model, system_prompt=system_prompt)
    except Exception as e:
        console.print(f"[red]Error creating target: {e}[/red]")
        sys.exit(1)

    # Parse attack list
    attack_list = attacks.split(",") if attacks else None

    # Run scan
    scanner = LLMGuardScanner(llm_target, budget_limit=budget)

    if not ci:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=15)

            # Wrap scan to update progress
            results = scanner.scan(attacks=attack_list, quick_mode=quick)
            progress.update(task, completed=len(results.get("all_results", [])))
    else:
        results = scanner.scan(attacks=attack_list, quick_mode=quick)

    # Report
    reporter = Reporter()

    if ci:
        import json
        click.echo(json.dumps(results, indent=2))
    else:
        reporter.print_terminal(results, console)

    # Save reports
    reporter.save_json(results, output)
    html_path = output.replace(".json", ".html")
    reporter.save_html(results, html_path)

    if not ci:
        console.print(f"\n[green]Reports saved:[/green] {output}, {html_path}")

    # Exit code based on risk score
    risk = results.get("summary", {}).get("risk_score", 0)
    if risk >= 80:
        sys.exit(2)
    elif risk > 0:
        sys.exit(1)
    sys.exit(0)


@cli.command()
def demo():
    """Run demo mode - no API key needed. Shows sample scan results."""
    from llmguard.demo import run_demo
    run_demo(console)


@cli.command("list")
def list_attacks():
    """List all available attacks grouped by category."""
    from llmguard.attacks.registry import ATTACK_REGISTRY, get_categories

    table = Table(title="LLMGuard Attacks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Category", style="magenta")
    table.add_column("Expected Rate", justify="right")

    for category in sorted(get_categories()):
        for attack_id, config in ATTACK_REGISTRY.items():
            if config["category"] == category:
                rate = f"{config['expected_success_rate']:.0%}"
                table.add_row(attack_id, config["name"], config["category"], rate)

    console.print(table)
    console.print(f"\n[dim]Total: {len(ATTACK_REGISTRY)} attacks[/dim]")


@cli.command()
@click.argument("attack_id")
def info(attack_id):
    """Show details about a specific attack."""
    from llmguard.attacks.registry import ATTACK_REGISTRY

    if attack_id not in ATTACK_REGISTRY:
        console.print(f"[red]Unknown attack: {attack_id}[/red]")
        console.print(f"[dim]Run 'llmguard list' to see available attacks.[/dim]")
        sys.exit(1)

    attack = ATTACK_REGISTRY[attack_id]

    console.print(Panel(
        f"[bold]{attack['name']}[/bold]\n\n"
        f"[cyan]ID:[/cyan] {attack_id}\n"
        f"[cyan]Category:[/cyan] {attack['category']}\n"
        f"[cyan]Test Cases:[/cyan] {attack['test_cases']}\n"
        f"[cyan]Expected Success Rate:[/cyan] {attack['expected_success_rate']:.0%}\n\n"
        f"[cyan]Description:[/cyan]\n{attack['description']}",
        title=f"Attack: {attack_id}",
        border_style="cyan"
    ))


if __name__ == "__main__":
    cli()
