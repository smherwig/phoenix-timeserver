Overview
========

Timeserver for the [Phoenix](https://github.com/smherwig/phoenix) SGX microkernel.


<a name="building"/> Building
=============================

The timeserver depends on [librho](https://github.com/smherwig/librho).  The
instructions here assume that librho is installed under `$HOME`; change the
`Makefile`'s `INCLUDES` variable if librho is installed to a different
directory.


Download and build the timeserver, `tntserver`:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-timeserver timeserver
cd timeserver
make
```

Generate a key pair (`timeserver-private.pem`, and `timeserver-public.pem`) for
the time server:

```
./gen_keypair.sh
mkdir -p ~/share/phoenix
cp timeserver-private.pem timeserver-public.pem ~/share/phoenix
```


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

The benchmarks require the [phoenix](https://github.com/smherwig/phoenix)
libOS and the
[phoenix-makemanifest](https://github.com/smherwig/phoenix-makemanifest)
configuration packager. Download and setup these two projects.  The
instructions here assume that the phoenix source is located at `$HOME/src/phoenix`
and the phoenix-makemanifest project at `$HOME/src/makemanifest`.

Next, build the timeserver benchmarking tool, `timebench`:

```
cd ~/src/timeserver/bench
make
```

`timebench` measures the elapsed time for an invocation of `gettimeofday`.
Specifically, `timebench` computes the elapsed time for *N* invocations of
`gettimeofday`, performs this test 10 times, and then takes the 30% trimmed
mean (mean of the middle four trials).


`timebench` is used to measure both configurations that retrieve time from
the host, as well as configurations that retrieve time from a time server.


Host Time Measurements
----------------------

These benchmarks do not use the timeserver.

### non-SGX

This simply measures the time for vanilla Linux to invoke `gettimeofday` one
million times.

```
cd ~/src/timeserver/bench
./timebench 1000000
```

### <a name="microbench-hosttime-sgx"/> SGX

Ensure that `~/src/phoenix/timeserver/bench/timebench.conf` appears as:

```
DEBUG off
EXEC file:$HOME/src/timeserver/bench/timebench
ENCLAVE_SIZE 128
THREADS 1
```

Package `timebench` to run on Graphene:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/timeserver/bench/timebench.conf -t $PWD -v -o timebench
```


Run the benchmark:

```
cd ~/src/makemanifest/timebench
./timebench.manifest.sgx 1000000
```


### exitless

For exitless system calls, change the `timebenchf.conf`'s `THREADS` directive
to:

```
THREADS 1 exitless
```

The rest of the steps are the same as for [SGX](#microbench-hosttime-sgx).


Timeserver Measurements
-----------------------

These benchmarks use the timeserver.  These benchmarks can take a long time to
run, so consider performing only 10,000 calls rather than one million.

### <a name="microbench-timeserver-sgx"/>SGX

The manifest file `~/src/phoenix/timeserver/bench/timebench.conf` should appear
as:

```
DEBUG off
EXEC file:$HOME/src/timeserver/bench/timebench
TIMESERVER udp:127.0.0.1:12345 $HOME/share/phoenix/timeserver-public.pem 1
ENCLAVE_SIZE 128
THREADS 1
```

Package `timebench` to run on Graphene:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/timeserver/bench/timebench.conf -t $PWD -v -o timebench
```

In one terminal, run the timeserver:

```
cd ~/src/timeserver
./tntserver -k ~/share/phoenix/timeserver-private.pem 12345
```

In the other terminal, run the timebench under Graphene:

```
cd ~/src/makemanifest/timebench
./timebench.manifest.sgx 10000
```

### exitless

For exitless system calls, change `timebench.conf`'s `THREADS` directive
to:

```
THREADS 1 exitless
```

The rest of the steps are the same as for [SGX](#microbench-timeserver-sgx).
