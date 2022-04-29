LICENSE: Apache 2.0
AUTHOR: Peter Boothe

Code vendored from https://github.com/m-lab/go/blob/master/memoryless/README.md

Functions which run a given function as a memoryless Poisson process.

This is very useful if your function generates a gauge measurement or it exerts load on the system in some way. By distributing the measurement or load across time, we help ensure that our systems' data is minimally affected.

