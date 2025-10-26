# COMP3821-Project

## To enable commits:

The repository is configured so that any commits must pass linting standards defined in the Makefile. To do this, you will need to install CPPlint:

**On macOS**:

```bash
brew install cpplint
```

**On Linux or Windows (ensure pip is installed)**:

```bash
pipx install cpplint
```

## Running the Project

1. Compile

Run:

```bash
make
```

Generate the executable in ./bin/testParse

2. Run the algorithm

Execute:

./bin/testParse

When prompted, choose:

d -> Deterministic Wu–Manber (prefix hash)

n -> Non-deterministic Wu–Manber (Bloom filter)

a -> Aho-Corasick

🧪 Example Output
=== Scanning: ./src/tests/pcaps/2017-07-29-BTCware-ransomware-from-cabeiriscout_faith.pcap ===

[Search Stats]
  Windows examined     : 238587
  Block size (B)       : 2
  Avg shift distance   : 0.927
  Hash hits            : 17393
  Chain traversals     : 1296365
  Exact matches        : 43209
  Elapsed time         : 0.008304 sec
  Throughput           : 27.40 MB/s
[+] Completed in 0.008324 seconds


That’s all you need — just make, run the binary, and pick your mode.

Make sure to run

```bash
make clean
```

before recompiling code. To check for linting, run

```bash
make lint
```
