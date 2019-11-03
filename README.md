Overview
========

Timeserver for the [Phoenix](https://github.com/smherwig/phoenix) SGX microkernel.


Building
========

The timeserver depends on [librho](https://github.com/smherwig/librho).  The
instructions here assume that librho is installed under `$HOME`; change the
`Makefile`'s `INCLUDES` variable if librho is installed to a different
directory.


To download and build the timeserver, enter:

```
cd ~/src
git clone https://github.com/smherwig/phoenix-timeserver timeserver
cd timeserver
make
```

To generate a key pair (`private.pem`, `public.pem`) for the time server,
enter:

```
./gen_keypair.sh
```


Micro-benchmarks
================

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

`timebench` measures the the elapsed time for an invocation of `gettimeofday`.
Specifically, `timebench` computes the elapsed time for *N* invocations of
`gettimeofday`, performs this test 10 times, and then takes the 30% trimmed
mean (mean of the middle four trials).


`timebench` is used to measure both configurations that retrieve time from
the host, as well as configurations that retrieve time from a time server.


Host Time Measurements
----------------------

### non-SGX

This simply tests the time for vanilla Linux to invoke `gettimeofday` one
million times.

```
cd ~/src/timeserver/bench
./timebench 1000000
```

### <a name="microbench-hosttime-sgx"/> SGX

The manifest file `~/src/phoenix/timeserver/bench/timebench.conf` should look
like:

```
EXEC file:/home/smherwig/src/timeserver/bench/timebench
ENCLAVE_SIZE 128 
THREADS 1
DEBUG off 
```

Change the executable path as needed.


Now, package `timebench` to run on Graphene:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p ~/src/timeserver/bench/timebench.conf -t $PWD -v -o timebench
cd timebench
cp manifest.sgx timebench.manifest.sgx
```


Run the benchmark:

```
cd ~/src/makemanifest/timebench
./timebench.manifest.sgx 100000
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

### <a name="microbench-timeserver-sgx"/>SGX

The manifest file `~/src/phoenix/timeserver/bench/timebench.conf` should look
like:

```
EXEC file:/home/smherwig/src/timeserver/bench/timebench
TIMESERVER udp:127.0.0.1:12345 /home/smherwig/src/timeserver/public.pem 1
ENCLAVE_SIZE 128 
THREADS 1
DEBUG off 
```

Next, package `timebench` to run on Graphene:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p ~/src/timeserver/bench/timebench.conf -t $PWD -v -o timebench
cd timebench
cp manifest.sgx timebench.manifest.sgx
```

In one terminal, run the timeserver:

```
./tntserver -k private.pem 12345
```

In the other terminal, run the timebench under Graphene:

```
cd ~/src/makemanifest/timebench
./timebench.manifest.sgx 100000
```

### exitless

For exitless system calls, change the `timebenchf.conf`'s `THREADS` directive
to:

```
THREADS 1 exitless
```

The rest of the steps are the same as for [SGX](#microbench-timeserver-sgx).
