import typer

from rich.console import Console
from rich.panel import Panel
from autoreconx.core.validator import validate_target
from autoreconx.core.scope import check_scope

app = typer.Typer(
    name="autoreconx",
    help="Automated Vulnerability Assessment Framework",
    add_completion=False
)

console = Console()


@app.command()
def version():
    """Display AutoReconX version."""

    console.print(
        Panel(
            "[bold cyan]AutoReconX[/bold cyan]\n"
            "Automated Vulnerability Assessment Framework\n"
            "Version: 0.1.0",
            title="Security Automation"
        )
    )


@app.command()
def info():
    """Display framework information."""

    console.print(
        "[bold green]AutoReconX initialized successfully![/bold green]"
    )
    console.print("Language: Python 3.13")
    console.print("Architecture: Modular")
    console.print("Scanner integrations: Pending")

@app.command()
def validate(target: str):
    """
    Validate an IP address, domain, or URL.
    """

    console.print("\n[bold cyan]AutoReconX Target Validation[/bold cyan]\n")

    try:
        result = validate_target(target)

        console.print(f"[bold]Target:[/bold] {target}")
        console.print(f"[bold]Host:[/bold] {result['host']}")
        console.print(f"[bold]Type:[/bold] {result['type']}")
        console.print(f"[bold]Scheme:[/bold] {result['scheme'] or 'N/A'}")
        console.print(f"[bold]Port:[/bold] {result['port'] or 'Default'}")

        console.print("\n[bold green]Validation: PASSED[/bold green]")
        console.print("[yellow]Authorization: NOT YET CONFIRMED[/yellow]")

    except ValueError as error:
        console.print(f"\n[bold red]Validation failed: {error}[/bold red]")
        raise typer.Exit(code=1)
@app.command()
def scope_check(target: str):
    """
    Check whether a target is in approved scope.
    """

    console.print("\n[bold cyan]AutoReconX Scope Verification[/bold cyan]\n")

    try:
        result = validate_target(target)

        authorized = check_scope(result["host"])

        console.print(f"Target: {target}")
        console.print(f"Host: {result['host']}")

        if authorized:
            console.print(
                "\n[bold green]SCOPE: APPROVED[/bold green]"
            )
        else:
            console.print(
                "\n[bold red]SCOPE: NOT APPROVED[/bold red]"
            )

    except (ValueError, FileNotFoundError) as error:
        console.print(f"[bold red]Error: {error}[/bold red]")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()