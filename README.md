# Some Linux IPC benchmarking

Blog post (TODO link)

This repo is a small collection of benchmarks to compare the performance of a few kernel mechanisms for IPC (signalling and data).

In particular, it compares eventfd vs pipes for waking up threads.

For exchanging messages between threads/processes, it compares using domain sockets vs UDP multicast, for various data sizes.

## Building

The benchmarks require CMake as well as [Google Benchmark](https://github.com/google/benchmark). Tested against v1.6.0.

```
# Get the code
git clone https://github.com/nikhilm/socket-ipc
cd socket-ipc

# Get Google Benchmark
curl -L "https://github.com/google/benchmark/archive/refs/tags/v1.6.0.tar.gz" | tar -zx
mv benchmark-1.6.0 benchmark

# Build
cmake -DBENCHMARK_DOWNLOAD_DEPENDENCIES=on -DCMAKE_BUILD_TYPE=Release -S . -B "build"
cmake --build "build" --config Release --target socket_bm
```

## Running

Using `taskset` to pin the process to a single CPU (on linux) is recommended to avoid scheduler noise.
```
taskset 0x00000001 ./build/socket_bm [--benchmark_repetitions=N]
```

## License

All code in this repo is under the public domain.
