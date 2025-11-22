# COMP3821 - Project

> Experimental framework for comparing classic multi-pattern string algorithms on packet capture (pcap) filess.

`bin/testParse` is produced from the implementations of Aho-Corasick, Set-Horspool, Boyer-Moore, and deterministic/probabilistic Wu-Manber variants in `src/`. 

`run_analysis.py` automates benchmarking against `.pcap` files and produces comparative tables and plots.

---

## Table of Contents

- [About The Project](#about-the-project)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Project Layout](#project-layout)
- [Linting](#linting)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)

---

## About The Project

This project implements a Network Intrusion Detection System (NIDS) benchmarking framework that evaluates the performance of several canonical string-matching algorithms under simulated network traffic conditions. The goal is to compare the effectiveness of these algorithms in detecting known patterns, focusing on their throughput, memory usage, and preprocessing time when applied to Snort-style rule sets.

We implemented five well known string-matching algorithms: Boyer-Moore, Set-Horspool, two variants of Wu-Manber, and Aho-Corasick, chosen for their relevance in both legacy and modern hybrid NIDS systems. The benchmarking framework allows you to run experiments on pcap files, enabling the comparison of different algorithms across real world network data.

### Built With

- C (GNU toolchain, `gcc` 9+ recommended)
- Python 3.8+ with `psutil`, `rich`, `matplotlib`
- GNU Make
- `cpplint` for style checks

[Back to top](#comp3821---project)

---

## Getting Started

To get a local copy up and running:

### Prerequisites

- Linux, macOS, or Windows via WSL.
- `gcc`, `make`, and Python 3.8+ available on `PATH`.
- Python packages for the analysis helper:
  ```bash
  python3 -m pip install --user psutil rich matplotlib
  ```
- `pipx install cpplint` (or `python3 -m pip install --user cpplint`) when you plan to run `make lint`.

Setup commands:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential make gcc python3 python3-pip

# macOS (Homebrew)
brew install gcc make python
```

Windows users should install WSL then ensure `make` and `gcc` resolve from the chosen shell.

### Installation

1. Clone the repository or zip download:
 
   ```bash
   git clone https://github.com/maggienesium/COMP3821-Project.git
   ```
2. Enter the repo directory and build the binary:

   ```bash
   make
   ```

   - Output: `bin/testParse`.
   - The build uses strict warnings (`-Werror`). On some compilers you can temporarily relax this via `make CFLAGS="$(CFLAGS) -Wno-error=unused-result"`.

3. (Optional) Clean artifacts with `make clean`.
4. (Optional) Validate style with `make lint` once `cpplint` is installed.

[Back to top](#comp3821---project)

---

## Usage

### Run the binary on a single capture

The current CLI expects the algorithm choice and `.pcap` path as positional arguments:

```bash
./bin/testParse <algorithm_key> <path_to_pcap>
```

Algorithm keys:

- `a`: Aho-Corasick
- `h`: Set-Horspool
- `d`: Wu-Manber (Deterministic)
- `p`: Wu-Manber (Probabilistic)
- `b`: Boyer-Moore

Example:

```bash
./bin/testParse a data/tests/pcaps/2018-01-04-Formbook-infection-traffic.pcap
```

### Automated analysis workflow

```bash
python3 run_analysis.py
```

- Ensures the project is compiled (`make`).
- Discovers `.pcap` files below `data/tests/pcaps/`.
- Runs each algorithm per capture, parsing stats such as throughput (MB/s), total shift distance, Bloom pass rates, preprocessing time, and memory estimates.
- Displays Rich tables per capture and writes `performance_analysis.png` summarizing metrics for the first successful run set.
- If Python dependencies are missing, the script attempts to install `psutil`, `rich`, and `matplotlib` automatically (you may be prompted for credentials depending on your environment).

[Back to top](#comp3821---project)

---

## Project Layout

- `Makefile` - build rules (strict `CFLAGS`, sanitizers, lint target).
- `bin/` - compiled artifacts (`bin/testParse`).
- `src/` - C sources (`parse/`, `algorithms/WM`, `algorithms/AC`, `algorithms/SH`, `algorithms/BM`).
- `data/tests/pcaps/` - packet captures used by `run_analysis.py`.
- `docs/` - supplementary write-ups (`docs/README_SETHORSPOOL.md`, etc.).
- `run_analysis.py` - benchmarking (see [Usage](#usage)).
- `3821-poster.pdf` - presentation artifact summarizing findings.

[Back to top](#comp3821---project)

---

## Linting

```bash
make lint
```

This wraps `cpplint --recursive src`. Install `cpplint` beforehand (see [Prerequisites](#prerequisites)). Update `CPPLINT.cfg` if you need to relax specific checks.

[Back to top](#comp3821---project)

---
## Contributing

The repository is configured so that any commits must pass linting standards defined in the Makefile. To do this, you will need to do the following

1. Fork the project and create a feature branch (`git checkout -b feature`).
2. Install cpplint so commits can pass the mandatory lint gate:
   - macOS:
     ```bash
     brew install cpplint
     ```
   - Linux / Windows (with pip available):
     ```bash
     pipx install cpplint
     ```
3. Build and lint before committing:
   ```bash
   make
   make lint
   ```
4. Commit your Changes (`git commit -m 'Add some feature'`)
5. Push to the Branch (`git push origin feature`)
6. Open a Pull Request

[Back to top](#comp3821---project)

---

## Troubleshooting

- **Warnings treated as errors:** The default build uses `-Werror`. Update your working tree (the current source checks `fread` results) or temporarily remove `-Werror` from `CFLAGS`.
- **Missing sanitizers:** The latest versions of Clang and GCC are recommended for full support of sanitizers like ASan and UBSan. Older versions may not support all sanitizer flags or may cause errors during compilation. Remove `-fsanitize=address -fsanitize=undefined` from `CFLAGS` if your compiler does not support them.
- **`make` not found on Windows:** Use WSL (Ubuntu), then ensure `make` is on PATH.
- **Python dependency errors:** Install compatible wheels via `python3 -m pip install --user 'numpy<2' 'matplotlib>=3.8' psutil rich` if the bundled distro packages conflict.
- **`make lint` fails:** The command simply surfaces cpplint findings; refer to the reported file/line list to decide whether to fix style issues or relax rules in `CPPLINT.cfg`.

[Back to top](#comp3821---project)
