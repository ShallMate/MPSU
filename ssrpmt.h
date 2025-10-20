
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

#include <iostream>
#include <vector>

#include "examples/mpsu/cuckoohash.h"
#include "examples/mpsu/okvs/galois128.h"
#include "examples/mpsu/opprf.h"
#include "examples/mpsu/peqt.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"

std::vector<int> SSRPMTRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                            std::vector<uint128_t>& elem_hashes,
                            okvs::Baxos sendbaxos, okvs::Baxos recvbaxos,
                            size_t cuckoolen) {
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

  return res;
}

std::vector<int> SSRPMTSend(const std::shared_ptr<yacl::link::Context>& ctx,
                            std::vector<uint128_t>& elem_hashes,
                            okvs::Baxos sendbaxos, okvs::Baxos recvbaxos,
                            CuckooHash& t_x) {
  size_t cuckoolen = t_x.cuckoolen_;
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");
  t_x.Insert(elem_hashes);
  t_x.Transform(r);
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
  return res;
}
