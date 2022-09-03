# Copyright 2018 Emery Hemingway

import std/bitops, std/endians

type
  Key* = array[16, uint8]
  HalfKey* = array[8, uint8]

{.push checks: off.}

template sipHash(result: array[8, byte]|array[16, byte]; data: openArray[byte]; key: Key; C, D: Natural) =
  assert(result.len in {8,16})
  var
    v0 = 0x736f6d6570736575'u64
    v1 = 0x646f72616e646f6d'u64
    v2 = 0x6c7967656e657261'u64
    v3 = 0x7465646279746573'u64
    b = uint64(data.len) shl 56

  for i in 0..7:
    v0 = v0 xor ((uint64(key[i+0]) shl (i shl 3)))
    v1 = v1 xor ((uint64(key[i+8]) shl (i shl 3)))
    v2 = v2 xor ((uint64(key[i+0]) shl (i shl 3)))
    v3 = v3 xor ((uint64(key[i+8]) shl (i shl 3)))

  when result.len == 16:
    v1 = v1 xor 0xee

  proc sipRound =
    v0 = v0 + v1
    v1 = rotateLeftBits(v1, 13)
    v1 = v1 xor v0
    v0 = rotateLeftBits(v0, 32) 
    v2 = v2 + v3
    v3 = rotateLeftBits(v3, 16)
    v3 = v3 xor v2
    v0 = v0 + v3
    v3 = rotateLeftBits(v3, 21)
    v3 = v3 xor v0
    v2 = v2 + v1
    v1 = rotateLeftBits(v1, 17)
    v1 = v1 xor v2
    v2 = rotateLeftBits(v2, 32)
  proc cRounds =
    for _ in 1..C: sipround()

  proc dRounds =
    for _ in 1..D: sipround()

  let left = data.len and 7
  for i in countup(0, (data.len-8)-left, 8):
    var m: uint64
    for j in 0..7:
      m = m or (uint64(data[i+j]) shl (j shl 3))
    v3 = v3 xor m
    cRounds()
    v0 = v0 xor m

  for i in data.len-left..data.high:
    b = b or (uint64(data[i]) shl ((i and 7) shl 3))

  v3 = v3 xor b
  cRounds()
  v0 = v0 xor b

  when result.len == 16:
    v2 = v2 xor 0xee
  else:
    v2 = v2 xor 0xff

  dROunds()
  b = v0 xor v1 xor v2 xor v3
  littleEndian64(addr result[0], addr b)

  when result.len == 16:
    v1 = v1 xor 0xdd
    dRounds()
    b = v0 xor v1 xor v2 xor v3
    littleEndian64(addr result[8], addr b)

template halfSipHash(result: array[4, uint8]|array[8, uint8]; data: openArray[uint8]; key: HalfKey; C, D: Natural) =
  var
    v0 = 0'u32
    v1 = 0'u32
    v2 = 0x6c796765'u32
    v3 = 0x74656462'u32
    b = uint32(data.len) shl 24

  for i in 0..3:
    v0 = v0 xor ((uint32(key[i+0]) shl (i shl 3)))
    v1 = v1 xor ((uint32(key[i+4]) shl (i shl 3)))
    v2 = v2 xor ((uint32(key[i+0]) shl (i shl 3)))
    v3 = v3 xor ((uint32(key[i+4]) shl (i shl 3)))

  when result.len == 8:
    v1 = v1 xor 0xee

  proc sipRound =
    v0 = v0 + v1
    v1 = rotateLeftBits(v1, 5)
    v1 = v1 xor v0
    v0 = rotateLeftBits(v0, 16) 
    v2 = v2 + v3
    v3 = rotateLeftBits(v3, 8)
    v3 = v3 xor v2
    v0 = v0 + v3
    v3 = rotateLeftBits(v3, 7)
    v3 = v3 xor v0
    v2 = v2 + v1
    v1 = rotateLeftBits(v1, 13)
    v1 = v1 xor v2
    v2 = rotateLeftBits(v2, 16)

  proc cRounds =
    for _ in 1..C: sipround()

  proc dRounds =
    for _ in 1..D: sipround()

  let left = data.len and 3
  for i in countup(0, (data.len-4)-left, 4):
    var m: uint32
    for j in 0..3:
      m = m or (uint32(data[i+j]) shl (j shl 3))
    v3 = v3 xor m
    cRounds()
    v0 = v0 xor m

  for i in data.len-left..data.high:
    b = b or (uint32(data[i]) shl ((i and 3) shl 3))

  v3 = v3 xor b
  cRounds()
  v0 = v0 xor b

  when result.len == 8:
    v2 = v2 xor 0xee
  else:
    v2 = v2 xor 0xff

  dROunds()
  b = v1 xor v3
  littleEndian32(addr result[0], addr b)

  when result.len == 8:
    v1 = v1 xor 0xdd
    dRounds()
    b = v1 xor v3
    littleEndian32(addr result[4], addr b)

func sipHash*(data: openArray[byte]; key: Key; C=2, D=4): array[8, byte] =
  ## The default version of SipHash returning 64-bit tags.
  sipHash(result, data, key, C, D)

func sipHashDouble*(data: openArray[byte]; key: Key; C=2, D=4): array[16, byte] =
  ## SipHash with doubled tag size, returning 128-bit tags.
  sipHash(result, data, key, C, D)

func halfSipHash*(data: openArray[byte]; key: HalfKey; C=2, D=4): array[4, byte] =
  ## A version of SipHash working with 32-bit words and returning 32-bit tags.
  halfSipHash(result, data, key, C, D)

func halfSipHashDouble*(data: openArray[byte]; key: HalfKey; C=2, D=4): array[8, byte] =
  ## HalfSipHash working with 32-bit words and returning 64-bit tags.
  halfSipHash(result, data, key, C, D)

{.pop.}
