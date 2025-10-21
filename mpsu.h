#pragma once

#include <cstddef>
#include <ostream>
#include <random>
#include <vector>

#include "examples/mpsu/cuckoohash.h"
#include "examples/mpsu/hesm2/ahesm2.h"
#include "examples/mpsu/hesm2/ciphertext.h"
#include "examples/mpsu/hesm2/private_key.h"
#include "examples/mpsu/ote.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

std::vector<uint128_t> GetInputsHash(std::vector<int32_t> &inputs) {
  std::vector<uint128_t> ret(inputs.size());
  yacl::parallel_for(0, inputs.size(), [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      ret[i] = yacl::crypto::Blake3_128(std::to_string(inputs[i]));
    }
  });
  return ret;
}

std::vector<int32_t> MPSUP1(const std::shared_ptr<yacl::link::Context> &ctx,
                            std::vector<int32_t> inputs,
                            const yacl::math::MPInt &k,
                            const hesm2::PublicKey &pk, uint128_t r) {
  size_t n = inputs.size();
  auto elem_hashes = GetInputsHash(inputs);
  uint32_t cuckoolen = static_cast<uint32_t>(n * 1.27);
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);
  std::vector<uint128_t> rs = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&r));
  for (size_t idx = 0; idx < elem_hashes.size(); ++idx) {
    __m128i x_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(&elem_hashes[idx]));
    size_t idx1 = idx * 3;
    uint64_t h = GetHash(1, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1] = Oracle(1, key_block, x_block);
    RS[idx1] = rs[h];
    h = GetHash(2, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1 + 1] = Oracle(2, key_block, x_block);
    RS[idx1 + 1] = rs[h];
    h = GetHash(3, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1 + 2] = Oracle(3, key_block, x_block);
    RS[idx1 + 2] = rs[h];
  }

  return inputs;
}

void MPSUPi(const std::shared_ptr<yacl::link::Context> &ctx,
            std::vector<int32_t> inputs, const yacl::math::MPInt &k,
            const hesm2::PublicKey &pk, uint128_t r) {
  size_t n = inputs.size();
  auto elem_hashes = GetInputsHash(inputs);
  uint32_t cuckoolen = static_cast<uint32_t>(n * 1.27);
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);
  std::vector<uint128_t> rs = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&r));
  for (size_t idx = 0; idx < elem_hashes.size(); ++idx) {
    __m128i x_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(&elem_hashes[idx]));
    size_t idx1 = idx * 3;
    uint64_t h = GetHash(1, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1] = Oracle(1, key_block, x_block);
    RS[idx1] = rs[h];
    h = GetHash(2, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1 + 1] = Oracle(2, key_block, x_block);
    RS[idx1 + 1] = rs[h];
    h = GetHash(3, elem_hashes[idx]) % cuckoolen;
    T_Y[idx1 + 2] = Oracle(3, key_block, x_block);
    RS[idx1 + 2] = rs[h];
  }
  CuckooHash t_x(n);
  t_x.Insert(elem_hashes, inputs);
  t_x.Transform(r);
  std::vector<hesm2::Ciphertext> T_X_ciphertexts(t_x.cuckoolen_);
  t_x.SM2EncTable(pk, T_X_ciphertexts);
}