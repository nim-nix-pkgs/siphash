import unittest

import ../src/siphash, vectors

suite "SipHash":
  const testHigh = 63

  template initKey(k: untyped) =
    for i in 0..k.high:
      k[i] = (uint8)i

  var
    key: siphash.Key
    halfKey: sipHash.HalfKey
    data = newSeq[byte]()
  initKey key
  initKey halfKey

  test "SipHash-2-4":
    for i in 0..testHigh:
      data.setLen(i)
      if i > 0:
        data[i-1] = (uint8)i-1
      let test = sipHash(data, key)
      check(test == vectors_sip64[i])

  test "SipHash-2-4 double":
    for i in 0..testHigh:
      data.setLen(i)
      if i > 0:
        data[i-1] = (uint8)i-1
      let test = sipHashDouble(data, key)
      check(test == vectors_sip128[i])

  test "Half SipHash-2-4":
    for i in 0..testHigh:
      data.setLen(i)
      if i > 0:
        data[i-1] = (uint8)i-1
      let test = halfSipHash(data, halfKey)
      check(test == vectors_hsip32[i])

  test "Half SipHash-2-4 double":
    for i in 0..testHigh:
      data.setLen(i)
      if i > 0:
        data[i-1] = (uint8)i-1
      let test = halfSipHashDouble(data, halfKey)
      check(test == vectors_hsip64[i])
