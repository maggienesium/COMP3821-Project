#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
COMP3821-Project: Algorithm Analysis Automation

This script automates the process of testing and comparing the performance of
the different string-matching algorithms implemented in this project.

It performs the following steps:
1.  Ensures the project is compiled by running 'make'.
2.  Finds all .pcap test files in the 'data/tests/pcaps/' directory.
3.  For each test file, it runs the './bin/testParse' executable with each
    of the available algorithms:
    - Aho-Corasick ('a')
    - Set-Horspool ('h')
    - Wu-Manber (Deterministic, 'd')
    - Wu-Manber (Probabilistic, 'p')
4.  It captures and parses the statistical output from each run.
5.  It measures the CPU time consumed by each algorithm during its run.
6.  Finally, it presents a formatted comparison table in the
    terminal for each test file.

Dependencies:
- psutil: For measuring CPU usage (`pip install psutil`)
- rich: For creating beautiful terminal tables (`pip install rich`)
- matplotlib: For generating performance plots (`pip install matplotlib`)

Usage:
- Make sure you have installed the dependencies.
- Run the script from the root of the project directory:
  python3 run_analysis.py
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

try:
    import psutil
    from rich.console import Console
    from rich.table import Table
    import matplotlib.pyplot as plt
except ImportError:
    print("Required Python packages not found. Attempting to install them...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "rich", "matplotlib"])
        # Retry importing after installation
        import psutil
        from rich.console import Console
        from rich.table import Table
        import matplotlib.pyplot as plt
        print("Packages installed successfully.")
    except Exception as e:
        print(f"Failed to install required packages: {e}", file=sys.stderr)
        print("Please install them manually by running: pip install psutil rich matplotlib", file=sys.stderr)
        sys.exit(1)

# --- Configuration ---
PROJECT_ROOT = Path(__file__).parent.resolve()
EXECUTABLE_NAME = "testParse.exe" if sys.platform == "win32" else "testParse"
EXECUTABLE_PATH = PROJECT_ROOT / "bin" / EXECUTABLE_NAME
PCAP_DIR = PROJECT_ROOT / "data" / "tests" / "pcaps"

ALGORITHMS = {
    "a": "Aho-Corasick",
    "h": "Set-Horspool",
    "d": "Wu-Manber (Det)",
    "p": "Wu-Manber (Prob)",
    "b": "Boyer-Moore",
}

# --- Main Logic ---

def compile_project():
    """Runs 'make' to ensure the executable is built and ready."""
    console = Console()
    console.print("[bold cyan]Step 1: Compiling project...[/bold cyan]")

    make_command = "make"
    if sys.platform == "win32":
        # On Windows, 'make' might not be in the PATH.
        # A common setup is using 'mingw32-make'.
        # This is a best-effort attempt.
        try:
            subprocess.run(["where", "mingw32-make"], check=True, capture_output=True)
            make_command = "mingw32-make"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass # Stick with 'make' and let it fail with a helpful message below

    try:
        process = subprocess.run(
            [make_command],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
        )
        console.print(f"[green]Project compiled successfully.[/green]\n")
        if process.stdout:
            console.print(f"[dim]{process.stdout}[/dim]")
    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] '{make_command}' command not found."
        )
        if sys.platform == "win32":
            console.print("On Windows, you need a 'make' environment like MinGW-w64 or MSYS2.")
            console.print("Install it, ensure 'mingw32-make.exe' is in your PATH, and try again.")
        else:
            console.print("Is 'make' installed and in your system's PATH?")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error:[/bold red] '{make_command}' failed with exit code {e.returncode}:")
        # Decode stderr if it's in bytes
        stderr_str = e.stderr
        if isinstance(stderr_str, bytes):
            try:
                stderr_str = stderr_str.decode('utf-8')
            except UnicodeDecodeError:
                stderr_str = str(e.stderr) # Fallback
        console.print(f"[red]{stderr_str}[/red]")
        sys.exit(1)


def find_pcap_files():
    """Finds all .pcap files in the specified directory."""
    console = Console()
    console.print(f"[bold cyan]Step 2: Searching for .pcap files in [yellow]{PCAP_DIR}[/yellow]...[/bold cyan]")
    if not PCAP_DIR.is_dir():
        console.print(f"[bold red]Error:[/bold red] Directory not found: {PCAP_DIR}")
        sys.exit(1)

    pcap_files = sorted(list(PCAP_DIR.rglob("*.pcap")))

    if not pcap_files:
        console.print(f"[bold red]Warning:[/bold red] No .pcap files found in {PCAP_DIR}.")
        sys.exit(1)

    console.print(f"[green]Found {len(pcap_files)} .pcap file(s).[/green]\n")
    return pcap_files


def parse_stats(output):
    """Parses the statistics from the executable's output using regex."""
    stats = {}

    # This pattern is a bit more general to catch the two different elapsed time formats
    patterns = {
        "Windows processed": r"Windows processed\s*:\s*([\d,\.]+)",
        "Total shift distance": r"Total shift distance\s*:\s*([\d,\.]+)",
        "Hash table hits": r"Hash table hits\s*:\s*([\d,\.]+)",
        "Bloom checks": r"Bloom checks\s*:\s*([\d,\.]+)",
        "Bloom positive checks": r"Bloom positive checks\s*:\s*([\d,\.]+)",
        "Chain traversal steps": r"Chain traversal steps\s*:\s*([\d,\.]+)",
        "Exact string matches": r"Exact string matches\s*:\s*([\d,\.]+)",
        "Verified post-Bloom": r"Verified post-Bloom\s*:\s*([\d,\.]+)",
        "Average shift length": r"Average shift length\s*:\s*([\d,\.]+)",
        "Avg. chain steps / hit": r"Avg\. chain steps / hit\s*:\s*([\d,\.]+)",
        "Bloom pass rate": r"Bloom pass rate\s*:\s*([\d,\.]+\s*%)",
        "Match rate (per window)": r"Match rate \(per window\)\s*:\s*([\d,\.]+\s*%)",
        "Elapsed time": r"Elapsed time\s*:\s*([\d.]+) sec",
        "Throughput": r"Throughput\s*:\s*([\d.]+\s*MB/s)",
        "Preprocessing-Time": r"Preprocessing-Time:\s*([\d\.]+)",
        "Ruleset-Count": r"Ruleset-Count:\s*(\d+)",
        "Ruleset-Avg-Length": r"Ruleset-Avg-Length:\s*([\d\.]+)",
        "Memory-Usage-MB": r"Total bytes used\s*:\s*\d+ bytes \(([\d\.]+) MB\)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            stats[key] = match.group(1).strip()

    # Fallback for algorithms that only print the final completion time
    if "Elapsed time" not in stats:
        match = re.search(r"Completed in ([\d.]+) seconds", output)
        if match:
            stats["Elapsed time"] = f"{match.group(1)} sec"

    return stats


def run_analysis(pcap_file):
    """Runs all algorithms on a single pcap file and returns the results."""
    console = Console()
    results = []

    if not EXECUTABLE_PATH.exists():
        console.print(f"[bold red]Error:[/bold red] Executable not found at {EXECUTABLE_PATH}.")
        console.print("Please run 'make' to compile the project.")
        sys.exit(1)

    for key, name in ALGORITHMS.items():
        try:
            process = subprocess.run(
                [str(EXECUTABLE_PATH), key, str(pcap_file)],
                capture_output=True,
                text=True,
                check=True,
                cwd=PROJECT_ROOT,
            )

            if process.returncode != 0:
                console.print(f"  [dim]Skipping [yellow]{name}[/yellow] due to runtime error.[/dim]")
                console.print(f"  [dim red]{process.stderr.strip()}[/dim red]")
                continue

            stats = parse_stats(process.stdout)
            stats["Algorithm"] = name
            results.append(stats)

        except FileNotFoundError:
            console.print(f"[bold red]Error:[/bold red] Executable not found: {EXECUTABLE_PATH}")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            console.print(f"  [dim]Skipping [yellow]{name}[/yellow] due to runtime error on {pcap_file.name}.[/dim]")
            console.print(f"  [dim red]{e.stderr.strip()}[/dim red]")
            continue
        except Exception as e:
            console.print(f"An unexpected error occurred with {name} on {pcap_file.name}: {e}")

    return results


def display_results(pcap_file, results):
    """Displays the results for a single pcap file in a beautiful table."""
    if not results:
        return

    console = Console()
    table = Table(
        title=f"Analysis for [bold magenta]{pcap_file.name}[/bold magenta]",
        show_header=True,
        header_style="bold cyan",
    )

    # Define columns
    table.add_column("Metric", style="dim", width=20)
    for result in results:
        table.add_column(result["Algorithm"], justify="right")

    # Get all unique metric keys from all results
    all_keys = sorted(list(set(key for res in results for key in res if key != "Algorithm")))

    # Add rows
    for key in all_keys:
        row_data = [key]
        for result in results:
            row_data.append(str(result.get(key, "N/A")))
        table.add_row(*row_data)

    console.print(table)
    console.print("\n")


def generate_plots(all_results):
    """Generates and saves plots based on the collected analysis data."""
    console = Console()
    console.rule("[bold blue]📊 Generating Performance Plots 📊[/bold blue]")

    if not all_results:
        console.print("[yellow]No results to plot.[/yellow]")
        return

    # --- Prepare data ---
    alg_names = [res['Algorithm'] for res in all_results]

    # Extract metrics, converting to float and handling missing values
    def get_metric(results, key, name, default=0.0):
        res = next((r for r in results if r.get('Algorithm') == name), None)
        if not res:
            return default
        val_str = res.get(key, str(default))
        # Clean up strings like 'MB/s' or '%' before converting
        val_str = val_str.replace('MB/s', '').replace('%', '').strip()
        try:
            return float(val_str)
        except (ValueError, TypeError):
            return default

    # Separate algorithms into two groups: fast and slow
    fast_algs = ['Aho-Corasick', 'Wu-Manber (Det)', 'Wu-Manber (Prob)']
    slow_algs = ['Set-Horspool', 'Boyer-Moore']
    
    fast_names = [name for name in alg_names if name in fast_algs]
    slow_names = [name for name in alg_names if name in slow_algs]

    # Extract metrics for each group
    fast_mem = [get_metric(all_results, 'Memory-Usage-MB', name) for name in fast_names]
    fast_throughput = [get_metric(all_results, 'Throughput', name) for name in fast_names]
    fast_prep = [get_metric(all_results, 'Preprocessing-Time', name) for name in fast_names]
    
    slow_mem = [get_metric(all_results, 'Memory-Usage-MB', name) for name in slow_names]
    slow_throughput = [get_metric(all_results, 'Throughput', name) for name in slow_names]
    slow_prep = [get_metric(all_results, 'Preprocessing-Time', name) for name in slow_names]

    # Ruleset stats are constant for the run, grab from the first valid result
    ruleset_count = get_metric(all_results, 'Ruleset-Count', alg_names[0])
    avg_len = get_metric(all_results, 'Ruleset-Avg-Length', alg_names[0])

    # --- Create Plots ---
    plt.style.use('seaborn-v0_8-darkgrid')
    # Create a 5x2 grid for 10 plots (5 metrics × 2 groups)
    fig, axs = plt.subplots(5, 2, figsize=(16, 24))
    fig.suptitle('Algorithm Performance Analysis - Separated by Performance Class', fontsize=22, weight='bold')

    # Row 0: Memory Usage vs. Number of Rules
    axs[0, 0].bar(fast_names, fast_mem, color='skyblue')
    axs[0, 0].set_title('Memory Usage - Fast Algorithms', fontsize=14, weight='bold')
    axs[0, 0].set_ylabel('Memory Usage (MB)', fontsize=12)
    axs[0, 0].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)
    
    axs[0, 1].bar(slow_names, slow_mem, color='lightsteelblue')
    axs[0, 1].set_title('Memory Usage - Slower Algorithms', fontsize=14, weight='bold')
    axs[0, 1].set_ylabel('Memory Usage (MB)', fontsize=12)
    axs[0, 1].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)

    # Row 1: Throughput vs. Number of Rules
    axs[1, 0].bar(fast_names, fast_throughput, color='lightcoral')
    axs[1, 0].set_title('Throughput - Fast Algorithms', fontsize=14, weight='bold')
    axs[1, 0].set_ylabel('Throughput (MB/s)', fontsize=12)
    axs[1, 0].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)
    
    axs[1, 1].bar(slow_names, slow_throughput, color='salmon')
    axs[1, 1].set_title('Throughput - Slower Algorithms', fontsize=14, weight='bold')
    axs[1, 1].set_ylabel('Throughput (MB/s)', fontsize=12)
    axs[1, 1].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)

    # Row 2: Preprocessing Time vs. Number of Rules
    axs[2, 0].bar(fast_names, fast_prep, color='mediumseagreen')
    axs[2, 0].set_title('Preprocessing Time - Fast Algorithms', fontsize=14, weight='bold')
    axs[2, 0].set_ylabel('Preprocessing Time (seconds)', fontsize=12)
    axs[2, 0].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)
    
    axs[2, 1].bar(slow_names, slow_prep, color='lightgreen')
    axs[2, 1].set_title('Preprocessing Time - Slower Algorithms', fontsize=14, weight='bold')
    axs[2, 1].set_ylabel('Preprocessing Time (seconds)', fontsize=12)
    axs[2, 1].set_xlabel(f"at {int(ruleset_count)} rules", fontsize=11)

    # Row 3: Throughput vs. Avg Pattern Length
    axs[3, 0].bar(fast_names, fast_throughput, color='plum')
    axs[3, 0].set_title('Throughput vs Pattern Length - Fast Algorithms', fontsize=14, weight='bold')
    axs[3, 0].set_ylabel('Throughput (MB/s)', fontsize=12)
    axs[3, 0].set_xlabel(f"at {avg_len:.2f} avg. length", fontsize=11)
    
    axs[3, 1].bar(slow_names, slow_throughput, color='orchid')
    axs[3, 1].set_title('Throughput vs Pattern Length - Slower Algorithms', fontsize=14, weight='bold')
    axs[3, 1].set_ylabel('Throughput (MB/s)', fontsize=12)
    axs[3, 1].set_xlabel(f"at {avg_len:.2f} avg. length", fontsize=11)

    # Row 4: Preprocessing Time vs. Avg Pattern Length
    axs[4, 0].bar(fast_names, fast_prep, color='sandybrown')
    axs[4, 0].set_title('Preprocessing vs Pattern Length - Fast Algorithms', fontsize=14, weight='bold')
    axs[4, 0].set_ylabel('Preprocessing Time (seconds)', fontsize=12)
    axs[4, 0].set_xlabel(f"at {avg_len:.2f} avg. length", fontsize=11)
    
    axs[4, 1].bar(slow_names, slow_prep, color='peachpuff')
    axs[4, 1].set_title('Preprocessing vs Pattern Length - Slower Algorithms', fontsize=14, weight='bold')
    axs[4, 1].set_ylabel('Preprocessing Time (seconds)', fontsize=12)
    axs[4, 1].set_xlabel(f"at {avg_len:.2f} avg. length", fontsize=11)

    # Improve layout for all subplots
    for i in range(5):
        for j in range(2):
            axs[i, j].tick_params(axis='x', rotation=15, labelsize=10)
            axs[i, j].grid(axis='y', linestyle='--', alpha=0.7)
            # Add value labels on bars with scientific notation for small values
            ax = axs[i, j]
            for container in ax.containers:
                # Custom formatter: use scientific notation if value < 0.01 or > 1000
                labels = []
                for bar in container:
                    val = bar.get_height()
                    if val == 0:
                        labels.append('0')
                    elif abs(val) < 0.01 and val != 0:
                        labels.append(f'{val:.2e}')
                    elif abs(val) > 1000:
                        labels.append(f'{val:.2e}')
                    else:
                        labels.append(f'{val:.3g}')
                ax.bar_label(container, labels=labels, padding=3, fontsize=9)

    plt.tight_layout(rect=[0, 0.01, 1, 0.99])

    plot_filename = "performance_analysis.png"
    try:
        plt.savefig(plot_filename, dpi=150)
        console.print(f"[green]✅ Plots saved to [bold]{plot_filename}[/bold][/green]\n")
    except Exception as e:
        console.print(f"[red]❌ Could not save plots: {e}[/red]")


def main():
    """Main function to orchestrate the analysis."""
    console = Console()
    console.rule("[bold green]🚀 Starting Algorithm Performance Analysis 🚀[/bold green]")

    compile_project()
    pcap_files = find_pcap_files()

    console.print("[bold cyan]Step 3: Running analysis on each .pcap file...[/bold cyan]\n")

    # We'll collect results from the first pcap file to use for plotting
    first_pcap_results = None

    for pcap_file in pcap_files:
        results = run_analysis(pcap_file)
        if results and not first_pcap_results:
            first_pcap_results = results
        display_results(pcap_file, results)

    # Generate plots based on the first valid set of results
    if first_pcap_results:
        generate_plots(first_pcap_results)

    console.rule("[bold green] Analysis Complete [/bold green]")
    console.print("A note on metrics:", style="dim")
    console.print(" - [bold]CPU Time[/bold] is the sum of user and system time the process spent on the CPU.", style="dim")
    console.print(" - [bold]GPU Usage[/bold] is not measured as these are CPU-bound algorithms.", style="dim")
    console.print(" - [bold]Accuracy[/bold] is represented by 'Exact matches', which is the number of patterns found.", style="dim")


if __name__ == "__main__":
    main()
