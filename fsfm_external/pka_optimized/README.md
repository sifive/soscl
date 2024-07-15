# Crypto primitives application

This application provides an example of the implementation of a low level algorithm with standard
Jacobian formulae. The Jacobian doubling algorithm 14 from [Rivain][1] was used as a reference.

## Results

```
Non-optimized double_jacobian:
  cycles: 25319
  ticks:  8627
Optimized double_jacobian:
  cycles: 23984
  ticks:  8175
```

[1]: https://www.matthieurivain.com/files/eprint11.pdf
