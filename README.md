Overview
========

Timeserver for the [Phoenix](https://github.com/smherwig/phoenix) SGX microkernel.


Building
========

```
cd ~/src
git clone https://github.com/smherwig/phoenix-timeserver timeserver
cd timeserver
make
```

```
./gen_keypair.sh
```



Micro-benchmarks
================

```
cd ~/src/timeserver/bench
make
```

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k enclave-key.pem -p ~/src/timeserver/bench/timebench.conf -t $PWD -v -o timebench
cd timebench
cp manifest.sgx timebench.manifest.sgx
```

In one terminal, run the server:

```
cd ~/src/timeserver
./tntserver -k private.pem 12345
```

In another terminal, run the client:

```
cd ~/src/makemanifest/timebench
./timebench.manifest.sgx 10000
```
