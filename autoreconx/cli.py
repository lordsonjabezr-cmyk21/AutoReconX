import ipaddress

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from autoreconx.core.validator import validate_target
from autoreconx.core.scope import (
    check_scope,
    load_allowed_ports,
    check_port_scope,
)
from autoreconx.scanners.nmap_scanner import (
    run_nmap,
    NmapScannerError,
)
from autoreconx.parsers.nmap_parser import (
    parse_nmap_xml,
    NmapParserError,
)

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


@app.command("nmap-scan")
def nmap_scan(
    target: str,
    confirm_authorized: bool = typer.Option(
        False,
        "--confirm-authorized",
        help="Confirm that you own the target or have explicit permission to scan it."
    )
):
    """
    Run a restricted Nmap scan against an approved localhost target.
    """

    console.print(
        "\n[bold cyan]AutoReconX - Nmap Assessment[/bold cyan]\n"
    )

    # 1. Require explicit authorization confirmation.
    if not confirm_authorized:
        console.print(
            "[bold red]Scan blocked: authorization confirmation required.[/bold red]"
        )
        console.print(
            "Use --confirm-authorized only after obtaining permission."
        )
        raise typer.Exit(code=1)

    try:
        # 2. Validate target syntax.
        target_info = validate_target(target)
        host = target_info["host"]

        # 3. Restrict this initial profile to loopback targets.
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host == "localhost"

        if not is_loopback:
            console.print(
                "[bold red]Scan blocked: this initial profile only supports localhost.[/bold red]"
            )
            raise typer.Exit(code=1)

        # 4. Enforce approved host scope.
        if not check_scope(host):
            console.print(
                "[bold red]Scan blocked: target is not in approved scope.[/bold red]"
            )
            raise typer.Exit(code=1)

        # 5. Load approved ports.
        ports = load_allowed_ports()

        if not check_port_scope(ports):
            console.print(
                "[bold red]Scan blocked: port scope verification failed.[/bold red]"
            )
            raise typer.Exit(code=1)

        console.print(f"[bold]Target:[/bold] {host}")
        console.print(f"[bold]Approved ports:[/bold] {ports}")
        console.print("[green]Host and port scope verified.[/green]\n")

        # 6. Execute Nmap.
        console.print("[yellow]Starting Nmap scan...[/yellow]")

        scan_result = run_nmap(
            target=host,
            ports=ports
        )

        console.print("[green]Nmap execution completed.[/green]")

        # 7. Parse XML output.
        parsed = parse_nmap_xml(scan_result["xml_file"])

        # 8. Display scan findings.
        table = Table(title="Nmap Scan Results")

        table.add_column("Port", style="cyan")
        table.add_column("Protocol")
        table.add_column("State")
        table.add_column("Service")
        table.add_column("Product")
        table.add_column("Version")

        open_count = 0

        for host_result in parsed["hosts"]:
            for port in host_result["ports"]:

                if port["state"] == "open":
                    open_count += 1

                    service = port["service"]

                    table.add_row(
                        str(port["port"]),
                        port["protocol"] or "unknown",
                        port["state"],
                        service.get("name") or "unknown",
                        service.get("product") or "unknown",
                        service.get("version") or "unknown"
                    )

        console.print(table)

        console.print(
            f"\n[bold green]Open ports discovered: {open_count}[/bold green]"
        )

        console.print(
            f"[bold]XML report:[/bold] {scan_result['xml_file']}"
        )

    except (ValueError, FileNotFoundError, NmapScannerError, NmapParserError) as error:
        console.print(f"\n[bold red]Scan failed: {error}[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()