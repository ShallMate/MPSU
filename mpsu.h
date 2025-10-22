#pragma once

#include <cstddef>
#include <iostream>
#include <vector>

#include "examples/mpsu/hesm2/ahesm2.h"
#include "examples/mpsu/hesm2/config.h"
#include "examples/mpsu/hesm2/private_key.h"
#include "examples/mpsu/mot.h"
#include "examples/mpsu/okvs/baxos.h"
#include "examples/mpsu/okvs/galois128.h"
#include "examples/mpsu/opprf.h"
#include "examples/mpsu/ote.h"
#include "examples/mpsu/shffuledec.h"
#include "examples/mpsu/ssrpmt.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/parallel.h"

std::vector<uint128_t> GetInputsHash(std::vector<int32_t>& inputs) {
  std::vector<uint128_t> ret(inputs.size());
  yacl::parallel_for(0, inputs.size(), [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      ret[i] = yacl::crypto::Blake3_128(std::to_string(inputs[i]));
    }
  });
  return ret;
}

std::vector<int32_t> CreateRangeItemsInt32(size_t begin, size_t size) {
  std::vector<int32_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(i + begin);
  }
  return ret;
}

void MPSU() {
  std::cout << "================= MPSU Test =================" << std::endl;
  std::cout << "HomoSM2 InitializeConfig" << std::endl;
  hesm2::InitializeConfig();

  size_t logn = 8;
  size_t n = 1 << logn;
  const int kWorldSize = 3;
  std::cout << "MPSU test with n = " << n << ", parties = " << kWorldSize
            << std::endl;
  std::cout << "Expected number of union elements: " << n + kWorldSize - 1
            << std::endl;

  std::cout << "Generating SM2 curve" << std::endl;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);

  std::cout << "Generating HomoSM2 key pair" << std::endl;
  hesm2::PrivateKey sk(ec, kWorldSize);
  const hesm2::PublicKey& pk = sk.GetPublicKey();

  std::cout << "Generating inputs for each party" << std::endl;
  std::vector<std::vector<int32_t>> inputs(kWorldSize);
  std::vector<std::vector<uint128_t>> inputs_uint128(kWorldSize);
  for (int i = 0; i < kWorldSize; i++) {
    inputs[i].resize(n);
    inputs_uint128[i].resize(n);
    inputs[i] = CreateRangeItemsInt32(i, n);
    inputs_uint128[i] = GetInputsHash(inputs[i]);
  }
  size_t sender_bin_size = n;
  size_t recv_bin_size = n;
  size_t weight = 3;
  size_t ssp = 40;
  uint32_t cuckoolen = static_cast<uint32_t>(n * 1.27);
  uint128_t r = yacl::crypto::FastRandU128();
  std::vector<std::vector<uint128_t>> TYs(kWorldSize);
  std::vector<std::vector<uint128_t>> rss(kWorldSize);
  std::vector<std::vector<uint128_t>> RSs(kWorldSize);

  std::cout << "Generating Simple hashing for each party" << std::endl;
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  for (size_t partyid = 0; partyid < kWorldSize; partyid++) {
    TYs[partyid].resize(n * 3);
    rss[partyid].resize(cuckoolen);
    rss[partyid] = yacl::crypto::RandVec<uint128_t>(cuckoolen);
    RSs[partyid].resize(n * 3);
    for (size_t idx = 0; idx < n; ++idx) {
      __m128i x_block = _mm_loadu_si128(
          reinterpret_cast<const __m128i*>(&inputs_uint128[partyid][idx]));
      size_t idx1 = idx * 3;
      uint64_t h = GetHash(1, inputs_uint128[partyid][idx]) % cuckoolen;
      TYs[partyid][idx1] = Oracle(1, key_block, x_block);
      RSs[partyid][idx1] = rss[partyid][h];
      h = GetHash(2, inputs_uint128[partyid][idx]) % cuckoolen;
      TYs[partyid][idx1 + 1] = Oracle(2, key_block, x_block);
      RSs[partyid][idx1 + 1] = rss[partyid][h];
      h = GetHash(3, inputs_uint128[partyid][idx]) % cuckoolen;
      TYs[partyid][idx1 + 2] = Oracle(3, key_block, x_block);
      RSs[partyid][idx1 + 2] = rss[partyid][h];
    }
  }
  std::cout << "Generating Cuckoo hashing and SM2 encryption for each party"
            << std::endl;
  std::vector<CuckooHash> T_xs(kWorldSize);
  std::vector<std::vector<hesm2::Ciphertext>> T_X_ciphertextss(kWorldSize);
  // T_X_ciphertextss[0] = GenZeroCiphertexts(cuckoolen, pk);
  for (size_t i = 1; i < kWorldSize; i++) {
    T_xs[i] = CuckooHash(n);
    T_xs[i].Insert(inputs_uint128[i], inputs[i]);
    T_xs[i].Transform(r);
    T_X_ciphertextss[i].resize(cuckoolen);
    T_xs[i].SM2EncTable(pk, T_X_ciphertextss[i]);
  }
  auto lctxs = yacl::link::test::SetupWorld(2);
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * 2 * cuckoolen;
  std::vector<uint8_t> buffer(total_length);
  // auto start_time = std::chrono::high_resolution_clock::now();

  for (size_t i = 0; i < kWorldSize; i++) {
    for (size_t j = i + 1; j < kWorldSize; j++) {
      // std::cout << "Party " << i << " and Party " << j << std::endl;
      okvs::Baxos sendbaxos;
      okvs::Baxos recvbaxos;
      uint128_t seed = yacl::crypto::FastRandU128();
      sendbaxos.Init(3 * n, sender_bin_size, weight, ssp,
                     okvs::PaxosParam::DenseType::GF128, seed);
      recvbaxos.Init(cuckoolen, recv_bin_size, weight, ssp,
                     okvs::PaxosParam::DenseType::GF128,
                     seed);  // setup network
      std::future<void> mot_rev = std::async(std::launch::async, [&] {
        return MOTRecv(lctxs[0], inputs_uint128[i], sendbaxos, recvbaxos,
                       cuckoolen, pk, r, TYs[i], rss[i], RSs[i]);
      });

      std::future<std::vector<hesm2::Ciphertext>> mot_sender =
          std::async(std::launch::async, [&] {
            return MOTSend(lctxs[1], inputs[j], inputs_uint128[j], sendbaxos,
                           recvbaxos, T_xs[j], pk, r);
          });

      mot_rev.get();
      auto prf_result = mot_sender.get();
      yacl::parallel_for(0, cuckoolen, [&](size_t begin, size_t end) {
        for (size_t idx = begin; idx < end; ++idx) {
          T_X_ciphertextss[j][idx] =
              hesm2::HAdd(T_X_ciphertextss[j][idx], prf_result[idx], pk);
        }
      });
    }
  }
  size_t com = lctxs[0]->GetStats()->sent_bytes.load() +
               lctxs[1]->GetStats()->sent_bytes.load();
  // cout << com << endl;
  auto newlctxs = yacl::link::test::SetupWorld(kWorldSize);
  auto ctx0 = newlctxs[0];
  std::future<std::vector<hesm2::Ciphertext>> f_p1;
  // 其他参与方（P2..Pn）
  std::vector<std::future<void>> fs1;
  fs1.reserve(kWorldSize - 1);
  f_p1 = std::async(std::launch::async,
                    [ctx0, ec, cuckoolen]() -> std::vector<hesm2::Ciphertext> {
                      return GetAllCiphersP1(ctx0, ec, cuckoolen);
                    });
  for (size_t i = 1; i < kWorldSize; ++i) {
    auto ctxi = newlctxs[i];
    ctxi->SetRecvTimeout(120000);

    fs1.emplace_back(std::async(
        std::launch::async, GetAllCiphersPi, ctxi, ec,
        std::ref(T_X_ciphertextss[i])  // 按引用传入真正的那一格
        ));
  }
  for (auto& f : fs1) f.get();
  auto allciphers = f_p1.get();
  size_t cipher_num = allciphers.size();

  // cout << "get all ciphers" << endl;
  // cout << cipher_num << endl;
  std::vector<std::future<void>> fs2;
  std::future<std::vector<int32_t>> fut_p1;
  fs2.reserve(kWorldSize - 1);
  ctx0->SetRecvTimeout(120000);
  const auto& ki = sk.GetKi(0);
  fut_p1 =
      std::async(std::launch::async,
                 [ctx0, &allciphers, ki, ec, pk]() -> std::vector<int32_t> {
                   return ShuffleAndDecP1(ctx0, allciphers, ki, ec, pk);
                 });

  for (size_t i = 1; i < kWorldSize; i++) {
    auto ctxi = newlctxs[i];
    ctxi->SetRecvTimeout(120000);
    const auto& kii = sk.GetKi(i);

    fs2.emplace_back(
        std::async(std::launch::async, [ctxi, kii, ec, cipher_num]() {
          ShuffleAndDecPi(ctxi, kii, ec, cipher_num);
        }));
  }
  for (auto& f : fs2) {
    f.get();
  }
  std::vector<int32_t> messages = fut_p1.get();
  // auto end_time = std::chrono::high_resolution_clock::now();
  // std::chrono::duration<double> duration = end_time - start_time;
  // std::cout << "Execution time: " << duration.count() << " seconds"
  //<< std::endl;
  std::unordered_set<int32_t> seen(inputs[0].begin(), inputs[0].end());
  for (auto& x : messages) {
    seen.insert(x);
  }

  std::vector<int32_t> result(seen.begin(), seen.end());

  std::cout << "The number of the union is " << result.size() << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto total_com = 0;
  for (int i = 0; i < kWorldSize; i++) {
    auto stats = newlctxs[i]->GetStats();
    total_com += stats->sent_bytes.load();
  }

  std::cout << "Total Communication: " << bytesToMB(total_com + com) << " MB"
            << std::endl;
}