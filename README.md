# Cache Simulator for EECS 582

## Installation
```bash
$ git clone https://github.com/Justin08784/cache-sim
$ cd cache-sim
$ git submodule update --init --recursive
```
The simulator was testing using the Linux kernel version 6.11.10. For the best results, run the profiler and simulator on a virtual machine using kernel version 6.11.10. This version of the kernel can be downloaded here: https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.11.10.tar.xz. 

## Usage

### Profiler
Profiler is the program that generates the log file of memory accesses. This log file is written to disk as page.log. The profiler will run until you stop it by pressing Ctrl-C. Use the following commands to compile and run the profiler.
```
$ make profiler
$ sudo ./profiler
```
### Simulator
Simulator is the program that reads the log file and simulates alternative policies. The file it tries to read from disk is page.log. Simulator has two optional command line arguments. The -s argument simulates evictions. This can be useful if you are profiling a higher end system under low memory pressure because you will not see any real evictions from the profiler. Thus, you can simulate a higher memory pressure with this flag. The -p argument prints the events to stdout. Use the following commands to compile and run the simulator.
```
$ make simulator
$ ./simulator [-p] [-s]
```
