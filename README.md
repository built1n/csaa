# Cloud Storage Assurance Architecture (CSAA) Proof-of-Concept

## Introduction

CSAA is a system first described in [Mohanty et
al.](https://fwei.tk/csass.pdf). It is designed to allow the secure
storage of data with an untrusted service provider, bootstrapping
trust from a "trusted module."

This program is an implementation of CSAA, adapted for use with
storing Docker containers. It should be considered research-quality
code, and does not (and can not!) provide any guarantees to the
trustworthiness of the trusted module, since it executes on a
general-purpose computer, in the same monolithic executable as the
untrusted service.

## Usage

### Prerequisites

You need the following packages for compiling and testing this
program: SQLite3, OpenSSL, GCC, G++, Make, and the `bc` calculator.

On Debian, type:

```
sudo apt-get install libsqlite3-dev libssl-dev sqlite3 make gcc g++ bc
```

### Compiling

```
make
```

This will produce three executables: `client`, `server`, and `postprocess`.

`client` and `server` implement the CSAA architecture; `postprocess`
is for processing timing data and generating graphs -- you should not
use it directly.

### Generating Timing Graphs

#### Prepopulating Databases

Edit `service_provider.c` and `dummy_service.c` to uncomment the
`PREPOPULATE` macro in each one, then recompile and run:

```
./prepopulate2.sh
./prepopulate_dummy.sh
```

This should populate the `databases` directory with prepopulated
databases and module states. This step only needs to be done once; the
generated databases can be re-used as needed.

#### Running Tests

Run `testmain_preinit.sh` with the desired logleaves range and number
of trials as its command-line arguments. For example, the following
will run logleaves 10-25 with 5 trials for each logleaves value:

```
./testmain_preinit.sh 10 25 5
```

This script will produce results in the `results` directory.

#### Producing Graphs

Run:

```
cd results
../tabulate.sh 10 25 5
```

Your working directory must be in the `results` directory for this to
work. The arguments to `tabulate.sh` must be exactly the same as those
passed to `testmain_preinit.sh`.

This step will produce many files with the prefix `final_` in the
`results` directory.

To use Gnuplot to produce graphs from these, change to the project
root directory and run:

```
./genlabels.sh
./graph.gnu
```

This will generate five graphs with the prefix `graph_`.
