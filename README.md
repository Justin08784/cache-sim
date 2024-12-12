# Cache simulator for EECS 582


## Installing

```bash
$ git clone https://github.com/Justin08784/cache-sim
$ cd cache-sim
$ git submodule update --init --recursive
# Profiler is the program that generates the log file of memory accesses
$ make profiler
$ sudo ./profiler
# Simulator is the program that reads the log file and simulates alternative policies
$ make simulator
$ ./simulator
```
