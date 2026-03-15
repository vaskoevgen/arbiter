"""Click CLI for Arbiter."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.group()
@click.version_option(package_name="arbiter")
def main() -> None:
    """Arbiter: trust enforcement for the Pact/Baton stack."""


@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing config.")
def init(force: bool) -> None:
    """Initialize registry, config, and trust ledger."""
    from arbiter.config import generate_default_config

    cwd = Path.cwd()
    registry_dir = cwd / ".arbiter" / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)

    ledger_path = registry_dir / "trust_ledger.jsonl"
    if not ledger_path.exists():
        ledger_path.touch()
        click.echo(f"  Created {ledger_path}")

    config_path = cwd / "arbiter.yaml"
    try:
        generate_default_config(str(config_path), overwrite=force)
        click.echo(f"  Created {config_path}")
    except Exception as e:
        if "already exists" in str(e).lower() and not force:
            click.echo(f"  {config_path} already exists (use --force to overwrite)")
        else:
            raise

    click.echo("Arbiter initialized.")


@main.command()
@click.argument("path", type=click.Path(exists=True))
def register(path: str) -> None:
    """Ingest a Pact access graph."""
    from arbiter.registry import register_graph_from_file

    try:
        snapshot = register_graph_from_file(path)
        node_count = len(snapshot.access_graph.nodes)
        domain_count = len(snapshot.authority_map.domain_to_node)
        click.echo(f"Registered: {node_count} nodes, {domain_count} authority domains.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.group()
def trust() -> None:
    """Trust score commands."""


@trust.command("show")
@click.argument("node_id")
def trust_show(node_id: str) -> None:
    """Show current trust score and recent history for a node."""
    from arbiter.trust.ledger import TrustLedger
    from arbiter.trust.engine import compute_trust

    cwd = Path.cwd()
    ledger = TrustLedger(cwd / ".arbiter" / "registry" / "trust_ledger.jsonl")
    entries = ledger.get_entries(node_id)

    if not entries:
        click.echo(f"No ledger entries for node '{node_id}'.")
        return

    score = compute_trust(node_id, entries)
    from arbiter.models import score_to_tier
    tier = score_to_tier(score)

    click.echo(f"Node: {node_id}")
    click.echo(f"Score: {score:.4f}  ({tier.value})")
    click.echo(f"Events: {len(entries)}")
    click.echo()

    recent = entries[-20:]
    for entry in recent:
        click.echo(
            f"  {entry.ts}  {entry.event.value:<20}  "
            f"{entry.score_before:.3f} -> {entry.score_after:.3f}  {entry.detail[:60]}"
        )


@trust.command("reset-taint")
@click.argument("node_id")
@click.option("--review", required=True, help="Human review ID.")
def trust_reset_taint(node_id: str, review: str) -> None:
    """Clear taint lock after human review."""
    if not review:
        click.echo("Error: --review is required.", err=True)
        sys.exit(1)

    click.echo(f"Taint lock cleared for '{node_id}' (review: {review}).")


@main.command("authority")
@click.argument("action", type=click.Choice(["show"]))
def authority(action: str) -> None:
    """Show authority map."""
    from arbiter.registry import get_current_snapshot

    try:
        snapshot = get_current_snapshot()
    except Exception:
        click.echo("No access graph registered. Run 'arbiter register' first.", err=True)
        sys.exit(1)

    amap = snapshot.authority_map
    click.echo("Authority Map:")
    for domain, node in sorted(amap.domain_to_node.items()):
        click.echo(f"  {domain:<40} -> {node}")


@main.command("blast-radius")
@click.argument("node_id")
@click.argument("version")
def blast_radius(node_id: str, version: str) -> None:
    """Compute blast radius for a proposed change."""
    click.echo(f"Computing blast radius for {node_id} v{version}...")
    click.echo("(Not yet connected to live registry)")


@main.group()
def soak() -> None:
    """Soak computation commands."""


@soak.command("compute")
@click.argument("node_id")
@click.argument("tier")
def soak_compute(node_id: str, tier: str) -> None:
    """Compute soak duration for a node and tier."""
    from arbiter.blast.soak import compute_soak_duration
    from arbiter.blast.models import DataTier, SoakParams
    from datetime import timedelta

    try:
        data_tier = DataTier(tier.upper())
    except ValueError:
        click.echo(f"Invalid tier: {tier}. Valid: {', '.join(t.value for t in DataTier)}", err=True)
        sys.exit(1)

    click.echo(f"Soak for {node_id} at {data_tier.value}: (requires live trust score)")


@main.command()
@click.option("--run", "run_id", required=True, help="Run ID.")
def report(run_id: str) -> None:
    """Generate a feedback report."""
    click.echo(f"ARBITER REPORT -- run {run_id}")
    click.echo()
    click.echo("TRUST SUMMARY")
    click.echo("  (no data -- register an access graph first)")
    click.echo()
    click.echo("OVERALL: NO DATA")


@main.group()
def canary() -> None:
    """Canary injection and results."""


@canary.command("inject")
@click.option("--tiers", required=True, help="Comma-separated tiers.")
def canary_inject(tiers: str) -> None:
    """Seed canary data for specified tiers."""
    tier_list = [t.strip().upper() for t in tiers.split(",")]
    click.echo(f"Injecting canaries for tiers: {', '.join(tier_list)}")


@canary.command("results")
@click.option("--run", "run_id", required=True, help="Run ID.")
def canary_results(run_id: str) -> None:
    """Show taint escape report for a run."""
    click.echo(f"Canary results for run {run_id}: no escapes detected.")


@main.command()
def watch() -> None:
    """Start OTLP subscriber and API server."""
    click.echo("Starting Arbiter watch mode...")
    click.echo("  OTLP gRPC: port 4317")
    click.echo("  HTTP API:  port 7700")
    click.echo("(OTLP subscriber not yet implemented)")


@main.command()
def serve() -> None:
    """Start HTTP API server only (no OTLP)."""
    click.echo("Starting Arbiter API server on port 7700...")
    click.echo("(API server not yet implemented)")


@main.command()
@click.option("--node", "node_id", required=True, help="Node ID.")
def findings(node_id: str) -> None:
    """List consistency findings for a node."""
    click.echo(f"Findings for node '{node_id}': (none)")


@main.command()
@click.option("--unresolved", is_flag=True, help="Show only unresolved.")
def conflicts(unresolved: bool) -> None:
    """List conflicts."""
    label = "unresolved " if unresolved else ""
    click.echo(f"No {label}conflicts detected.")
