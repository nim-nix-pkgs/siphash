# SipHash

SipHash is an add–rotate–xor (ARX) based family of pseudorandom functions.
It may be used to implement hash tables with resistence to hash flooding.

See: https://en.wikipedia.org/wiki/SipHash

## Usage

```nim
import hashes

proc hash(s: string): Hash =
  var key: siphash.Key
    # this is a keyed hash function, use a zero key
  let b: array[8, byte] = sipHash(toOpenArrayByte(s, s.low, s.high), key)
    # the hash fuction operates over byte arrays
  result = cast[Hash](b)
    # casting or converting is up to you
```
