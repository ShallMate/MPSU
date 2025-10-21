
// Copyright 2025 Guowei LING.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#pragma once

#include <utility>
#include <vector>

#include "examples/mpsu/cuckoohash.h"
#include "examples/mpsu/hesm2/ciphertext.h"
#include "examples/mpsu/opprf.h"
#include "examples/mpsu/ote.h"
#include "examples/mpsu/peqt.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/serialize.h"

std::vector<hesm2::Ciphertext> GenRandomLargeCiphertexts(
    size_t num, const hesm2::PublicKey& public_key) {
  auto p = public_key.GetEcGroup()->GetOrder();
  std::vector<hesm2::Ciphertext> ciphertexts(num);
  yacl::parallel_for(0, num, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      yacl::math::MPInt m;
      yacl::math::MPInt::RandomLtN(p, &m);
      ciphertexts[idx] = hesm2::Encrypt(m, public_key);
    }
  });
  return ciphertexts;
}

std::vector<hesm2::Ciphertext> GenZeroCiphertexts(
    size_t num, const hesm2::PublicKey& public_key) {
  std::vector<hesm2::Ciphertext> ciphertexts(num);
  yacl::parallel_for(0, num, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      yacl::math::MPInt m(0);
      ciphertexts[idx] = hesm2::Encrypt(m, public_key);
    }
  });
  return ciphertexts;
}

std::vector<int> MOTRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<uint128_t>& elem_hashes,
                         okvs::Baxos sendbaxos, okvs::Baxos recvbaxos,
                         size_t cuckoolen,
                         std::shared_ptr<yacl::crypto::EcGroup> ec) {
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);
  std::vector<uint128_t> rs = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  for (size_t idx = 0; idx < elem_hashes.size(); ++idx) {
    __m128i x_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
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
  std::future<void> opprf_sender = std::async(std::launch::async, [&] {
    opprf::OPPRFSend(ctx, T_Y, RS, sendbaxos, recvbaxos);
  });
  opprf_sender.get();
  std::vector<uint64_t> out(cuckoolen);
  std::transform(rs.begin(), rs.end(), out.begin(),
                 [](uint128_t x) { return static_cast<uint64_t>(x); });

  std::future<std::vector<int>> fut1 = std::async(std::launch::async, [&] {
    return RunOnePartyEquality(ctx, out, ctx->Rank());
  });
  std::vector<int> res = fut1.get();
  auto choose = yacl::dynamic_bitset<>(res.size());
  for (size_t i = 0; i != res.size(); ++i) {
    choose[i] = static_cast<bool>(res[i]);
  }
  std::vector<hesm2::Ciphertext> outputs(cuckoolen);
  auto recv_future = std::async(std::launch::async,
                                [&] { outputs = SM2OTERecv(ctx, choose, ec); });
  recv_future.get();

  return res;
}

std::vector<int> MOTSend(const std::shared_ptr<yacl::link::Context>& ctx,
                         std::vector<int32_t> items_b_int32,
                         std::vector<uint128_t>& elem_hashes,
                         okvs::Baxos sendbaxos, okvs::Baxos recvbaxos,
                         CuckooHash& t_x, const hesm2::PublicKey& public_key) {
  size_t cuckoolen = t_x.cuckoolen_;
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");
  t_x.Insert(elem_hashes, std::move(items_b_int32));
  t_x.Transform(r);
  std::vector<hesm2::Ciphertext> T_X_ciphertexts(t_x.cuckoolen_);
  std::vector<hesm2::Ciphertext> Random_Ciphertexts =
      GenRandomLargeCiphertexts(t_x.cuckoolen_, public_key);
  std::vector<hesm2::Ciphertext> Zero_Ciphertexts =
      GenZeroCiphertexts(t_x.cuckoolen_, public_key);

  t_x.SM2EncTable(public_key, T_X_ciphertexts);
  std::future<std::vector<uint128_t>> opprf_receiver = std::async(
      std::launch::async,
      [&] { return opprf::OPPRFRecv(ctx, t_x.bins_, sendbaxos, recvbaxos); });
  std::vector<uint128_t> prf_result = opprf_receiver.get();
  std::vector<uint64_t> out(cuckoolen);
  std::transform(prf_result.begin(), prf_result.end(), out.begin(),
                 [](uint128_t x) { return static_cast<uint64_t>(x); });
  std::future<std::vector<int>> fut0 = std::async(std::launch::async, [&] {
    return RunOnePartyEquality(ctx, out, ctx->Rank());
  });
  std::vector<int> res = fut0.get();
  std::vector<hesm2::Ciphertext> ciphers0(cuckoolen);
  std::vector<hesm2::Ciphertext> ciphers1(cuckoolen);
  for (size_t i = 0; i != cuckoolen; ++i) {
    if (res[i] == 0) {
      ciphers0[i] = Zero_Ciphertexts[i];
      ciphers1[i] = Random_Ciphertexts[i];
    } else {
      ciphers0[i] = Random_Ciphertexts[i];
      ciphers1[i] = Zero_Ciphertexts[i];
    }
  }
  auto send_future = std::async(std::launch::async, [&] {
    SM2OTESend(ctx, ciphers0, ciphers1, public_key.GetEcGroup());
  });
  send_future.get();
  return res;
}
