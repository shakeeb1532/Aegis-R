from __future__ import annotations
from rich.console import Console
from rich.table import Table

console = Console()


class ConsoleEmitter:
    """Human-friendly console output for decisions."""

    def emit(self, decision: dict) -> None:
        print_decision(decision)

def print_decision(d: dict) -> None:
    t = Table(title="noisegraph decision", show_lines=True)
    t.add_column("field")
    t.add_column("value", overflow="fold")
    t.add_row("ts", d.get("ts",""))
    t.add_row("decision", d.get("decision",""))
    t.add_row("risk", str(d.get("risk","")))
    t.add_row("incident_id", d.get("incident_id",""))
    t.add_row("reasons", ", ".join(d.get("reasons",[])))
    t.add_row("explain", d.get("explain",""))
    if d.get("policy_overridden"):
        t.add_row("policy_override", d.get("policy_overridden",""))
    ev = d.get("event", {})
    t.add_row("template", ev.get("template",""))
    t.add_row("entity", str(ev.get("entity",{})))
    console.print(t)
