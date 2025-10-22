#include <cstddef>
#include <iostream>
#include <vector>

#include "examples/mpsu/hesm2/ahesm2.h"
#include "examples/mpsu/hesm2/config.h"
#include "examples/mpsu/hesm2/private_key.h"
#include "examples/mpsu/mot.h"
#include "examples/mpsu/mpsu.h"
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

using yacl::crypto::EcGroupFactory;
using namespace hesm2;

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint128_t> CreateInputHashes(std::vector<int32_t>& inputs) {
  std::vector<uint128_t> ret(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(inputs[i])));
  }
  return ret;
}

std::vector<int32_t> CreateRangeItemsInt32(size_t size) {
  std::vector<int32_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(i);
  }
  return ret;
}

int RunOPPRF() {
  size_t logn = 16;
  const uint64_t ns = 1.3 * (1 << logn);
  const uint64_t nr = 3 * (1 << logn);
  size_t sender_bin_size = ns;
  size_t recv_bin_size = nr;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  sendbaxos.Init(ns, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(nr, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_c = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> opprf_sender = std::async(std::launch::async, [&] {
    opprf::OPPRFSend(lctxs[0], items_a, items_b, sendbaxos, recvbaxos);
  });

  std::future<std::vector<uint128_t>> opprf_receiver =
      std::async(std::launch::async, [&] {
        return opprf::OPPRFRecv(lctxs[1], items_c, sendbaxos, recvbaxos);
      });

  opprf_sender.get();
  auto prf_result = opprf_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  if (std::equal(prf_result.begin(), prf_result.end(), items_b.begin())) {
    std::cout << "items_b and prf_result are equal." << std::endl;
  } else {
    std::cout << "items_b and prf_result are not equal." << std::endl;
  }

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunSSRPMT() {
  size_t logn = 16;
  const uint64_t ns = 1 << logn;
  const uint64_t nr = 1 << logn;
  size_t sender_bin_size = ns;
  size_t recv_bin_size = nr;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  sendbaxos.Init(3 * nr, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(cuckoolen, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);

  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<int>> opprf_sender =
      std::async(std::launch::async, [&] {
        return SSRPMTRecv(lctxs[0], items_a, sendbaxos, recvbaxos, cuckoolen);
      });

  std::future<std::vector<int>> opprf_receiver = std::async(
      std::launch::async,
      [&] { return SSRPMTSend(lctxs[1], items_b, sendbaxos, recvbaxos, T_X); });

  auto prf_result1 = opprf_sender.get();
  auto prf_result = opprf_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  size_t match_count = 0;
  for (size_t i = 0; i < cuckoolen; i++) {
    int res = prf_result1[i] ^ prf_result[i];
    if (res == 1) {
      match_count++;
    }
    // cout << res << endl;
  }
  cout << "match count: " << match_count << endl;

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunSM2() {
  // 参数配置并读取预计算表
  InitializeConfig();

  // 生成SM2椭圆曲线群
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 1;
  }

  // 公私钥对生成
  PrivateKey private_key(std::move(ec_group));
  const auto& public_key = private_key.GetPublicKey();

  // 指定明文
  auto m1 = yacl::math::MPInt(100);
  auto m2 = yacl::math::MPInt(6);

  // 加密
  auto c1 = Encrypt(m1, public_key);
  auto c2 = Encrypt(m2, public_key);

  // 标量乘，即密文乘明文
  auto c3 = HMul(c1, m2, public_key);

  // 同态加，即密文加密文
  auto c4 = HAdd(c1, c2, public_key);

  // 单线程解密
  auto res3 = Decrypt(c3, private_key);

  // 并发解密
  auto res4 = ParDecrypt(c4, private_key);

  // 打印结果
  std::cout << res3.m << std::endl;
  std::cout << res4.m << std::endl;

  // 打印是否解密正确
  std::cout << res3.success << std::endl;
  std::cout << res4.success << std::endl;

  return 0;
}

void TestOTECorrectness() {
  size_t num_ot = 1 << 20;  // 1M OTs
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  std::vector<uint128_t> m0s = yacl::crypto::RandVec<uint128_t>(num_ot);
  std::vector<uint128_t> m1s = yacl::crypto::RandVec<uint128_t>(num_ot);

  auto chooses = yacl::crypto::SecureRandBits(num_ot);
  std::vector<uint128_t> outputs;

  // Receiver 线程
  auto recv_future = std::async(
      std::launch::async, [&] { outputs = OTERecv(contexts[0], chooses); });

  // Sender 线程
  auto send_future =
      std::async(std::launch::async, [&] { OTESend(contexts[1], m0s, m1s); });

  recv_future.get();
  send_future.get();

  // 校验结果
  size_t mismatch = 0;
  for (size_t i = 0; i < num_ot; ++i) {
    uint128_t expected = chooses[i] ? m1s[i] : m0s[i];
    if (outputs[i] != expected) {
      std::cerr << "❌ Mismatch at index " << i << std::endl;
      ++mismatch;
    }
  }

  if (mismatch == 0) {
    std::cout << "✅ OTE correctness test passed (" << num_ot << " OTs)."
              << std::endl;
  } else {
    std::cout << "❌ OTE test failed: " << mismatch << " mismatches found."
              << std::endl;
  }
}

void TestHomoOTECorrectness() {
  size_t num_ot = 1 << 16;  // 1M OTs
  const int kWorldSize = 2;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  std::vector<yacl::crypto::EcPoint> m0s = GenRandomPoints(num_ot, ec);
  std::vector<yacl::crypto::EcPoint> m1s = GenRandomPoints(num_ot, ec);
  auto chooses = yacl::crypto::SecureRandBits(num_ot);
  std::vector<yacl::crypto::EcPoint> outputs;

  // Receiver 线程
  auto recv_future = std::async(std::launch::async, [&] {
    outputs = HomoOTERecv(contexts[0], chooses, ec);
  });

  // Sender 线程
  auto send_future = std::async(
      std::launch::async, [&] { HomoOTESend(contexts[1], m0s, m1s, ec); });

  recv_future.get();
  send_future.get();
  // cout << "get outputs" << endl;

  // 校验结果
  size_t mismatch = 0;
  for (size_t i = 0; i < num_ot; ++i) {
    yacl::crypto::EcPoint expected = chooses[i] ? m1s[i] : m0s[i];
    if (!ec->PointEqual(outputs[i], expected)) {
      std::cerr << "❌ Mismatch at index " << i << std::endl;
      ++mismatch;
    }
  }

  if (mismatch == 0) {
    std::cout << "✅ OTE correctness test passed (" << num_ot << " OTs)."
              << std::endl;
  } else {
    std::cout << "❌ OTE test failed: " << mismatch << " mismatches found."
              << std::endl;
  }
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void TestSM2OTECorrectness() {
  size_t num_ot = 1 << 12;
  const int kWorldSize = 2;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  hesm2::PrivateKey sk(ec);
  const hesm2::PublicKey& pk = sk.GetPublicKey();
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  std::vector<hesm2::Ciphertext> m0s = GenRandomCiphertexts(num_ot, pk);
  std::vector<hesm2::Ciphertext> m1s = GenRandomCiphertexts(num_ot, pk);
  std::cout << "gen random ciphertexts done" << std::endl;
  auto chooses = yacl::crypto::SecureRandBits(num_ot);
  std::vector<hesm2::Ciphertext> outputs;

  // Receiver 线程
  auto recv_future = std::async(std::launch::async, [&] {
    outputs = SM2OTERecv(contexts[0], chooses, ec);
  });

  // Sender 线程
  auto send_future = std::async(std::launch::async,
                                [&] { SM2OTESend(contexts[1], m0s, m1s, ec); });

  recv_future.get();
  send_future.get();
  // cout << "get outputs" << endl;

  // 校验结果
  size_t mismatch = 0;
  for (size_t i = 0; i < num_ot; ++i) {
    hesm2::Ciphertext expected = chooses[i] ? m1s[i] : m0s[i];
    if ((!ec->PointEqual(outputs[i].GetC1(), expected.GetC1())) ||
        (!ec->PointEqual(outputs[i].GetC2(), expected.GetC2()))) {
      std::cerr << "❌ Mismatch at index " << i << std::endl;
      ++mismatch;
    }
  }

  if (mismatch == 0) {
    std::cout << "✅ OTE correctness test passed (" << num_ot << " OTs)."
              << std::endl;
  } else {
    std::cout << "❌ OTE test failed: " << mismatch << " mismatches found."
              << std::endl;
  }
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

int RunMutiSM2() {
  // 参数配置并读取预计算表
  InitializeConfig();

  // 生成SM2椭圆曲线群
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 1;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  size_t partynum = 4;
  // 公私钥对生成
  PrivateKey private_key(ec, partynum);
  const auto& public_key = private_key.GetPublicKey();

  std::vector<hesm2::Ciphertext> ciphers =
      GenRandomCiphertexts(1 << 12, public_key);
  // const auto& sk = private_key.GetK();
  // std::cout << "gen random ciphertexts done" << std::endl;
  // randomzie
  std::vector<hesm2::Ciphertext> reciphertexts =
      RerandomizeCiphertextsWithYacl(ciphers, public_key);
  // shuffle
  auto perm = GenShuffledRangeWithYacl(reciphertexts.size());
  std::vector<hesm2::Ciphertext> shuffled_ciphertexts =
      ShuffleWithYacl(reciphertexts, perm);

  // buffer to point
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * 2 * shuffled_ciphertexts.size();
  std::vector<uint8_t> buffer_c1(total_length);
  std::vector<uint8_t> buffer(total_length);
  CiphertextstoBuffer(absl::MakeSpan(shuffled_ciphertexts),
                      absl::MakeSpan(buffer), ec);
  std::vector<hesm2::Ciphertext> buffered_ciphertexts(
      shuffled_ciphertexts.size());
  BuffertoCiphertexts(absl::MakeSpan(buffered_ciphertexts),
                      absl::MakeSpan(buffer), ec);

  // decrypt
  for (size_t i = 0; i < buffered_ciphertexts.size(); ++i) {
    auto res4 =
        hesm2::MutiDecrypt(buffered_ciphertexts[i], private_key, partynum);
    std::cout << res4.m << std::endl;
  }

  return 0;
}

int RunMutiSM2Dec() {
  // 参数配置并读取预计算表
  InitializeConfig();

  // 生成SM2椭圆曲线群
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 1;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  size_t partynum = 4;
  // 公私钥对生成
  PrivateKey private_key(ec, partynum);
  const auto& public_key = private_key.GetPublicKey();
  size_t num_cipher = 1 << 12;
  std::vector<hesm2::Ciphertext> ciphers =
      GenRandomCiphertexts(num_cipher, public_key);
  std::vector<yacl::crypto::EcPoint> c1_points(num_cipher);
  std::vector<yacl::crypto::EcPoint> c2_points(num_cipher);
  for (size_t i = 0; i < num_cipher; i++) {
    c1_points[i] = ciphers[i].GetC1();
    c2_points[i] = ciphers[i].GetC2();
  }
  // std::cout << "gen random ciphertexts done" << std::endl;
  for (size_t i = 1; i < partynum; ++i) {
    auto di = private_key.GetKi(i);
    yacl::parallel_for(0, num_cipher, [&](size_t begin, size_t end) {
      for (size_t j = begin; j < end; ++j) {
        auto temp = ec->Mul(c1_points[j], di);
        c2_points[j] = ec->Sub(c2_points[j], temp);
      }
    });
  }
  // new construct ciphertexts
  std::vector<hesm2::Ciphertext> final_ciphertexts(num_cipher);
  yacl::parallel_for(0, num_cipher, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      final_ciphertexts[i] = hesm2::Ciphertext(c1_points[i], c2_points[i]);
    }
  });

  // decrypt
  for (size_t i = 0; i < final_ciphertexts.size(); ++i) {
    auto res4 =
        hesm2::DecryptforInt(final_ciphertexts[i], ec, private_key.GetKi(0));
    std::cout << res4.m << std::endl;
  }

  return 0;
}

void RunShuffleTest() {
  InitializeConfig();
  const int kWorldSize = 3;
  size_t logn = 12;
  const uint64_t n = 1 << logn;
  size_t num_cipher = static_cast<uint32_t>(n * 1.27) * kWorldSize;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  hesm2::PrivateKey sk(ec, kWorldSize);
  const hesm2::PublicKey& pk = sk.GetPublicKey();
  std::vector<hesm2::Ciphertext> ciphers = GenRandomCiphertexts(num_cipher, pk);
  std::cout << "gen random ciphertexts done" << std::endl;
  auto lctxs = yacl::link::test::SetupWorld(kWorldSize);  // Initialize lctxs
  std::future<std::vector<int32_t>> fut_p1;
  // 其他参与方（P2..Pn）
  std::vector<std::future<void>> futs;
  futs.reserve(kWorldSize - 1);
  const size_t cipher_num = ciphers.size();
  auto ctx0 = lctxs[0];
  lctxs[0]->SetRecvTimeout(120000);
  const auto& ki = sk.GetKi(0);
  // const auto& kk = sk.GetK();
  fut_p1 = std::async(std::launch::async,
                      [ctx0, &ciphers, ki, ec, pk]() -> std::vector<int32_t> {
                        return ShuffleAndDecP1(ctx0, ciphers, ki, ec, pk);
                      });

  for (size_t i = 1; i < kWorldSize; i++) {
    auto ctxi = lctxs[i];
    lctxs[i]->SetRecvTimeout(120000);
    const auto& kii = sk.GetKi(i);

    futs.emplace_back(
        std::async(std::launch::async, [ctxi, kii, ec, cipher_num]() {
          ShuffleAndDecPi(ctxi, kii, ec, cipher_num);
        }));
  }
  for (auto& f : futs) {
    f.get();
  }
  std::vector<int32_t> messages = fut_p1.get();
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto total_com = 0;
  for (int i = 0; i < kWorldSize; i++) {
    auto stats = lctxs[i]->GetStats();
    total_com += stats->sent_bytes.load();
  }
  std::cout << "Total Communication: " << bytesToMB(total_com) << " MB"
            << std::endl;
}

int RunMOT() {
  InitializeConfig();
  const int kWorldSize = 5;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 0;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  hesm2::PrivateKey sk(ec, kWorldSize);
  const hesm2::PublicKey& pk = sk.GetPublicKey();

  size_t logn = 12;
  const uint64_t ns = 1 << logn;
  const uint64_t nr = 1 << logn;
  size_t sender_bin_size = ns;
  size_t recv_bin_size = nr;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  // cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  sendbaxos.Init(3 * nr, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(cuckoolen, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  std::vector<int32_t> items_a_int32 = CreateRangeItemsInt32(ns);
  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);

  std::vector<int32_t> items_b_int32 = CreateRangeItemsInt32(nr);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<int>> opprf_sender =
      std::async(std::launch::async, [&] {
        return MOTRecv(lctxs[0], items_a, sendbaxos, recvbaxos, cuckoolen, ec);
      });

  std::future<std::vector<int>> opprf_receiver =
      std::async(std::launch::async, [&] {
        return MOTSend(lctxs[1], items_b_int32, items_b, sendbaxos, recvbaxos,
                       T_X, pk);
      });

  auto prf_result1 = opprf_sender.get();
  auto prf_result = opprf_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  size_t match_count = 0;
  for (size_t i = 0; i < cuckoolen; i++) {
    int res = prf_result1[i] ^ prf_result[i];
    if (res == 1) {
      match_count++;
    }
    // cout << res << endl;
  }
  cout << "match count: " << match_count << endl;

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunMOTV2() {
  InitializeConfig();
  const int kWorldSize = 5;
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 0;
  }
  std::shared_ptr<yacl::crypto::EcGroup> ec = std::move(ec_group);
  hesm2::PrivateKey sk(ec, kWorldSize);
  const hesm2::PublicKey& pk = sk.GetPublicKey();

  size_t logn = 12;
  const uint64_t ns = 1 << logn;
  const uint64_t nr = 1 << logn;
  size_t sender_bin_size = ns;
  size_t recv_bin_size = nr;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos sendbaxos;
  okvs::Baxos recvbaxos;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  // cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  sendbaxos.Init(3 * nr, sender_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  recvbaxos.Init(cuckoolen, recv_bin_size, weight, ssp,
                 okvs::PaxosParam::DenseType::GF128, seed);
  std::vector<int32_t> items_a_int32 = CreateRangeItemsInt32(ns);
  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);

  std::vector<int32_t> items_b_int32 = CreateRangeItemsInt32(nr);
  std::vector<uint128_t> items_b = CreateRangeItems(0, nr);

  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  uint128_t r = yacl::crypto::FastRandU128();
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  std::vector<uint128_t> T_Y(items_a.size() * 3);
  std::vector<uint128_t> rs = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(items_a.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  for (size_t idx = 0; idx < items_a.size(); ++idx) {
    __m128i x_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&items_a[idx]));
    size_t idx1 = idx * 3;
    uint64_t h = GetHash(1, items_a[idx]) % cuckoolen;
    T_Y[idx1] = Oracle(1, key_block, x_block);
    RS[idx1] = rs[h];
    h = GetHash(2, items_a[idx]) % cuckoolen;
    T_Y[idx1 + 1] = Oracle(2, key_block, x_block);
    RS[idx1 + 1] = rs[h];
    h = GetHash(3, items_a[idx]) % cuckoolen;
    T_Y[idx1 + 2] = Oracle(3, key_block, x_block);
    RS[idx1 + 2] = rs[h];
  }
  T_X.Insert(items_b, items_b_int32);
  T_X.Transform(r);
  std::vector<hesm2::Ciphertext> T_X_ciphertexts(T_X.cuckoolen_);
  T_X.SM2EncTable(pk, T_X_ciphertexts);
  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> mot_rev = std::async(std::launch::async, [&] {
    return MOTRecv(lctxs[0], items_a, sendbaxos, recvbaxos, cuckoolen, pk, r,
                   T_Y, rs, RS);
  });

  std::future<std::vector<hesm2::Ciphertext>> mot_sender =
      std::async(std::launch::async, [&] {
        return MOTSend(lctxs[1], items_b_int32, items_b, sendbaxos, recvbaxos,
                       T_X, pk, r);
      });

  mot_rev.get();
  auto prf_result = mot_sender.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int main() {
  // RunMOT();
  // RunSSRPMT();
  // RunShuffleTest();
  // RunMPSU();
  // RunMOTV2();
  MPSU();
}