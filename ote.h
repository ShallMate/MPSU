#pragma once

#include <iostream>
#include <vector>

#include "examples/mpsu/hesm2/ahesm2.h"
#include "examples/mpsu/hesm2/ciphertext.h"
#include "examples/mpsu/hesm2/private_key.h"
#include "fmt/format.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;
using namespace std;

inline std::vector<uint8_t> FillVecWithPrg(const uint128_t& seed,
                                           size_t point_size) {
  std::vector<uint8_t> vec(point_size);
  if (point_size == 0) {
    return vec;
  }
  yacl::crypto::Prg<uint8_t> prng(seed);
  prng.Fill(absl::MakeSpan(vec));
  return vec;
}

inline std::vector<uint8_t> XORPoints(std::vector<uint8_t> a,
                                      std::vector<uint8_t> b,
                                      size_t point_size) {
  std::vector<uint8_t> res(point_size);
  for (size_t i = 0; i < point_size; ++i) {
    res[i] = a[i] ^ b[i];
  }
  return res;
}

std::vector<yacl::crypto::EcPoint> GenRandomPoints(
    size_t num, std::shared_ptr<yacl::crypto::EcGroup> ec) {
  std::vector<yacl::crypto::EcPoint> points(num);
  yacl::parallel_for(0, num, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      yacl::math::MPInt r;
      yacl::math::MPInt::RandomLtN(ec->GetOrder(), &r);
      points[idx] = ec->MulBase(r);
    }
  });
  return points;
}

std::vector<hesm2::Ciphertext> GenRandomCiphertexts(
    size_t num, const hesm2::PublicKey& public_key) {
  std::vector<hesm2::Ciphertext> ciphertexts(num);
  std::vector<int32_t> messages = yacl::crypto::RandVec<int32_t>(num);
  yacl::parallel_for(0, num, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      yacl::math::MPInt m(messages[idx]);
      ciphertexts[idx] = hesm2::Encrypt(m, public_key);
    }
  });
  return ciphertexts;
}

void PointstoBuffer(absl::Span<yacl::crypto::EcPoint> in,
                    absl::Span<std::uint8_t> buffer,
                    std::shared_ptr<yacl::crypto::EcGroup> ec) {
  uint64_t point_size = ec->GetSerializeLength();
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * point_size;
      ec->SerializePoint(in[idx], buffer.data() + offset, point_size);
    }
  });
}

void BuffertoPoints(absl::Span<yacl::crypto::EcPoint> in,
                    absl::Span<std::uint8_t> buffer,
                    std::shared_ptr<yacl::crypto::EcGroup> ec) {
  uint64_t point_size = ec->GetSerializeLength();
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * point_size;
      in[idx] = ec->DeserializePoint(
          absl::MakeSpan(buffer.data() + offset, point_size));
    }
  });
}

vector<uint128_t> OTERecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          const yacl::dynamic_bitset<>& chooses) {
  size_t num_ot = chooses.size();
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto rand_bits = yacl::crypto::SecureRandBits(num_ot);
  auto store = ss_receiver.GenRot(ctx, rand_bits);
  yacl::dynamic_bitset<> bbs(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    bbs[i] = chooses[i] ^ rand_bits[i];
  }
  const auto* bit_ptr = reinterpret_cast<const std::byte*>(bbs.data());
  size_t byte_len = bbs.num_blocks() * sizeof(decltype(*bbs.data()));

  ctx->SendAsync(ctx->NextRank(), yacl::ByteContainerView(bit_ptr, byte_len),
                 "Send bbs_bytes");

  auto buf = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts0");
  auto buf1 = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts1");
  std::vector<uint128_t> ciphers0(num_ot);
  std::vector<uint128_t> ciphers1(num_ot);
  std::memcpy(ciphers0.data(), buf.data(), buf.size());
  std::memcpy(ciphers1.data(), buf1.data(), buf1.size());
  std::vector<uint128_t> elems(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    if (chooses[i]) {
      elems[i] = ciphers1[i] ^ store.GetBlock(i);
    } else {
      elems[i] = ciphers0[i] ^ store.GetBlock(i);
    }
  }
  return elems;
}

void OTESend(const std::shared_ptr<yacl::link::Context>& ctx,
             const std::vector<uint128_t>& m0s,
             const std::vector<uint128_t>& m1s) {
  YACL_ENFORCE(m0s.size() == m1s.size(), "m0s and m1s must have the same size");
  size_t num_ot = m0s.size();
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Recev bbs_bytes");

  yacl::dynamic_bitset<> bbs(num_ot);
  std::memcpy(bbs.data(), buf.data(), buf.size());

  std::vector<uint128_t> ciphers0(num_ot);
  std::vector<uint128_t> ciphers1(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    ciphers0[i] = m0s[i] ^ store.GetBlock(i, bbs[i] ? 1 : 0);
    ciphers1[i] = m1s[i] ^ store.GetBlock(i, bbs[i] ? 0 : 1);
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers0.data(),
                                         ciphers0.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers1.data(),
                                         ciphers1.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
}

vector<yacl::crypto::EcPoint> HomoOTERecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const yacl::dynamic_bitset<>& chooses,
    const std::shared_ptr<yacl::crypto::EcGroup>& ec) {
  size_t num_ot = chooses.size();
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto rand_bits = yacl::crypto::SecureRandBits(num_ot);
  auto store = ss_receiver.GenRot(ctx, rand_bits);
  yacl::dynamic_bitset<> bbs(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    bbs[i] = chooses[i] ^ rand_bits[i];
  }
  const auto* bit_ptr = reinterpret_cast<const std::byte*>(bbs.data());
  size_t byte_len = bbs.num_blocks() * sizeof(decltype(*bbs.data()));

  ctx->SendAsync(ctx->NextRank(), yacl::ByteContainerView(bit_ptr, byte_len),
                 "Send bbs_bytes");

  auto buf = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts0");
  auto buf1 = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts1");
  uint64_t point_size = ec->GetSerializeLength();
  uint64_t total_length = point_size * num_ot;
  std::vector<uint8_t> ciphers0(total_length);
  std::vector<uint8_t> ciphers1(total_length);
  std::memcpy(ciphers0.data(), buf.data(), buf.size());
  std::memcpy(ciphers1.data(), buf1.data(), buf1.size());
  std::vector<yacl::crypto::EcPoint> elems(num_ot);
  std::vector<std::vector<uint8_t>> res(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    if (chooses[i]) {
      res[i] = XORPoints(
          std::vector<uint8_t>(ciphers1.data() + i * point_size,
                               ciphers1.data() + (i + 1) * point_size),
          FillVecWithPrg(store.GetBlock(i), point_size), point_size);
    } else {
      res[i] = XORPoints(
          std::vector<uint8_t>(ciphers0.data() + i * point_size,
                               ciphers0.data() + (i + 1) * point_size),
          FillVecWithPrg(store.GetBlock(i), point_size), point_size);
    }
  }
  std::vector<uint8_t> flat(total_length);
  for (size_t i = 0; i != num_ot; ++i) {
    std::memcpy(flat.data() + i * point_size, res[i].data(), point_size);
  }
  BuffertoPoints(absl::MakeSpan(elems), absl::MakeSpan(flat), ec);
  return elems;
}

void HomoOTESend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<yacl::crypto::EcPoint>& m0s,
                 std::vector<yacl::crypto::EcPoint>& m1s,
                 const std::shared_ptr<yacl::crypto::EcGroup>& ec) {
  YACL_ENFORCE(m0s.size() == m1s.size(), "m0s and m1s must have the same size");
  size_t num_ot = m0s.size();
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Recev bbs_bytes");

  yacl::dynamic_bitset<> bbs(num_ot);
  std::memcpy(bbs.data(), buf.data(), buf.size());
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * num_ot;
  std::vector<uint8_t> m0sbuffer(total_length);
  std::vector<uint8_t> m1sbuffer(total_length);
  PointstoBuffer(absl::MakeSpan(m0s), absl::MakeSpan(m0sbuffer), ec);
  PointstoBuffer(absl::MakeSpan(m1s), absl::MakeSpan(m1sbuffer), ec);
  std::vector<std::vector<uint8_t>> ciphers0(num_ot);
  std::vector<std::vector<uint8_t>> ciphers1(num_ot);
  std::vector<uint8_t> flat0(total_length);
  std::vector<uint8_t> flat1(total_length);

  for (size_t i = 0; i != num_ot; ++i) {
    ciphers0[i] =
        XORPoints(std::vector<uint8_t>(m0sbuffer.data() + i * point_size,
                                       m0sbuffer.data() + (i + 1) * point_size),
                  FillVecWithPrg(store.GetBlock(i, bbs[i] ? 1 : 0), point_size),
                  point_size);
    ciphers1[i] =
        XORPoints(std::vector<uint8_t>(m1sbuffer.data() + i * point_size,
                                       m1sbuffer.data() + (i + 1) * point_size),
                  FillVecWithPrg(store.GetBlock(i, bbs[i] ? 0 : 1), point_size),
                  point_size);
  }

  for (size_t i = 0; i != num_ot; ++i) {
    std::memcpy(flat0.data() + i * point_size, ciphers0[i].data(), point_size);
    std::memcpy(flat1.data() + i * point_size, ciphers1[i].data(), point_size);
  }
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(flat0.data(), flat0.size() * sizeof(uint8_t)),
      "Send ciphertexts");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(flat1.data(), flat1.size() * sizeof(uint8_t)),
      "Send ciphertexts");
}

vector<hesm2::Ciphertext> SM2OTERecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const yacl::dynamic_bitset<>& chooses,
    const std::shared_ptr<yacl::crypto::EcGroup>& ec) {
  size_t num_ot = chooses.size();
  std::vector<yacl::crypto::EcPoint> outputs1;
  auto recv_future = std::async(
      std::launch::async, [&] { outputs1 = HomoOTERecv(ctx, chooses, ec); });
  recv_future.get();
  std::vector<yacl::crypto::EcPoint> outputs2;
  auto recv_future1 = std::async(
      std::launch::async, [&] { outputs2 = HomoOTERecv(ctx, chooses, ec); });
  recv_future1.get();
  std::vector<hesm2::Ciphertext> outputs(num_ot);
  for (size_t i = 0; i < num_ot; ++i) {
    outputs[i] = hesm2::Ciphertext(outputs1[i], outputs2[i]);
  }
  return outputs;
}

void SM2OTESend(const std::shared_ptr<yacl::link::Context>& ctx,
                std::vector<hesm2::Ciphertext>& m0s,
                std::vector<hesm2::Ciphertext>& m1s,
                const std::shared_ptr<yacl::crypto::EcGroup>& ec) {
  size_t num_ot = m0s.size();
  std::vector<yacl::crypto::EcPoint> m0_points_c1(num_ot);
  std::vector<yacl::crypto::EcPoint> m0_points_c2(num_ot);
  std::vector<yacl::crypto::EcPoint> m1_points_c1(num_ot);
  std::vector<yacl::crypto::EcPoint> m1_points_c2(num_ot);
  for (size_t i = 0; i < num_ot; ++i) {
    m0_points_c1[i] = m0s[i].GetC1();
    m0_points_c2[i] = m0s[i].GetC2();
    m1_points_c1[i] = m1s[i].GetC1();
    m1_points_c2[i] = m1s[i].GetC2();
  }
  auto send_future = std::async(std::launch::async, [&] {
    HomoOTESend(ctx, m0_points_c1, m1_points_c1, ec);
  });
  send_future.get();
  auto send_future1 = std::async(std::launch::async, [&] {
    HomoOTESend(ctx, m0_points_c2, m1_points_c2, ec);
  });
  send_future1.get();
}

vector<yacl::crypto::EcPoint> HomoOTERecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const yacl::dynamic_bitset<>& chooses,
    const std::shared_ptr<yacl::crypto::EcGroup>& ec, size_t other_party_rank) {
  size_t num_ot = chooses.size();
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto rand_bits = yacl::crypto::SecureRandBits(num_ot);
  auto store = ss_receiver.GenRot(ctx, rand_bits);
  yacl::dynamic_bitset<> bbs(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    bbs[i] = chooses[i] ^ rand_bits[i];
  }
  const auto* bit_ptr = reinterpret_cast<const std::byte*>(bbs.data());
  size_t byte_len = bbs.num_blocks() * sizeof(decltype(*bbs.data()));

  ctx->SendAsync(other_party_rank, yacl::ByteContainerView(bit_ptr, byte_len),
                 "Send bbs_bytes");

  auto buf = ctx->Recv(other_party_rank, "Recv ciphertexts0");
  auto buf1 = ctx->Recv(other_party_rank, "Recv ciphertexts1");
  uint64_t point_size = ec->GetSerializeLength();
  uint64_t total_length = point_size * num_ot;
  std::vector<uint8_t> ciphers0(total_length);
  std::vector<uint8_t> ciphers1(total_length);
  std::memcpy(ciphers0.data(), buf.data(), buf.size());
  std::memcpy(ciphers1.data(), buf1.data(), buf1.size());
  std::vector<yacl::crypto::EcPoint> elems(num_ot);
  std::vector<std::vector<uint8_t>> res(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    if (chooses[i]) {
      res[i] = XORPoints(
          std::vector<uint8_t>(ciphers1.data() + i * point_size,
                               ciphers1.data() + (i + 1) * point_size),
          FillVecWithPrg(store.GetBlock(i), point_size), point_size);
    } else {
      res[i] = XORPoints(
          std::vector<uint8_t>(ciphers0.data() + i * point_size,
                               ciphers0.data() + (i + 1) * point_size),
          FillVecWithPrg(store.GetBlock(i), point_size), point_size);
    }
  }
  std::vector<uint8_t> flat(total_length);
  for (size_t i = 0; i != num_ot; ++i) {
    std::memcpy(flat.data() + i * point_size, res[i].data(), point_size);
  }
  BuffertoPoints(absl::MakeSpan(elems), absl::MakeSpan(flat), ec);
  return elems;
}

void HomoOTESend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<yacl::crypto::EcPoint>& m0s,
                 std::vector<yacl::crypto::EcPoint>& m1s,
                 const std::shared_ptr<yacl::crypto::EcGroup>& ec,
                 size_t other_party_rank) {
  YACL_ENFORCE(m0s.size() == m1s.size(), "m0s and m1s must have the same size");
  size_t num_ot = m0s.size();
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, num_ot);
  auto buf = ctx->Recv(other_party_rank, "Recev bbs_bytes");

  yacl::dynamic_bitset<> bbs(num_ot);
  std::memcpy(bbs.data(), buf.data(), buf.size());
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * num_ot;
  std::vector<uint8_t> m0sbuffer(total_length);
  std::vector<uint8_t> m1sbuffer(total_length);
  PointstoBuffer(absl::MakeSpan(m0s), absl::MakeSpan(m0sbuffer), ec);
  PointstoBuffer(absl::MakeSpan(m1s), absl::MakeSpan(m1sbuffer), ec);
  std::vector<std::vector<uint8_t>> ciphers0(num_ot);
  std::vector<std::vector<uint8_t>> ciphers1(num_ot);
  std::vector<uint8_t> flat0(total_length);
  std::vector<uint8_t> flat1(total_length);

  for (size_t i = 0; i != num_ot; ++i) {
    ciphers0[i] =
        XORPoints(std::vector<uint8_t>(m0sbuffer.data() + i * point_size,
                                       m0sbuffer.data() + (i + 1) * point_size),
                  FillVecWithPrg(store.GetBlock(i, bbs[i] ? 1 : 0), point_size),
                  point_size);
    ciphers1[i] =
        XORPoints(std::vector<uint8_t>(m1sbuffer.data() + i * point_size,
                                       m1sbuffer.data() + (i + 1) * point_size),
                  FillVecWithPrg(store.GetBlock(i, bbs[i] ? 0 : 1), point_size),
                  point_size);
  }

  for (size_t i = 0; i != num_ot; ++i) {
    std::memcpy(flat0.data() + i * point_size, ciphers0[i].data(), point_size);
    std::memcpy(flat1.data() + i * point_size, ciphers1[i].data(), point_size);
  }
  ctx->SendAsync(
      other_party_rank,
      yacl::ByteContainerView(flat0.data(), flat0.size() * sizeof(uint8_t)),
      "Send ciphertexts");
  ctx->SendAsync(
      other_party_rank,
      yacl::ByteContainerView(flat1.data(), flat1.size() * sizeof(uint8_t)),
      "Send ciphertexts");
}

vector<hesm2::Ciphertext> SM2OTERecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const yacl::dynamic_bitset<>& chooses,
    const std::shared_ptr<yacl::crypto::EcGroup>& ec, size_t other_party_rank) {
  size_t num_ot = chooses.size();
  std::vector<yacl::crypto::EcPoint> outputs1;
  auto recv_future = std::async(std::launch::async, [&] {
    outputs1 = HomoOTERecv(ctx, chooses, ec, other_party_rank);
  });
  recv_future.get();
  std::vector<yacl::crypto::EcPoint> outputs2;
  auto recv_future1 = std::async(std::launch::async, [&] {
    outputs2 = HomoOTERecv(ctx, chooses, ec, other_party_rank);
  });
  recv_future1.get();
  std::vector<hesm2::Ciphertext> outputs(num_ot);
  for (size_t i = 0; i < num_ot; ++i) {
    outputs[i] = hesm2::Ciphertext(outputs1[i], outputs2[i]);
  }
  return outputs;
}

void SM2OTESend(const std::shared_ptr<yacl::link::Context>& ctx,
                std::vector<hesm2::Ciphertext>& m0s,
                std::vector<hesm2::Ciphertext>& m1s,
                const std::shared_ptr<yacl::crypto::EcGroup>& ec,
                size_t other_party_rank) {
  size_t num_ot = m0s.size();
  std::vector<yacl::crypto::EcPoint> m0_points_c1(num_ot);
  std::vector<yacl::crypto::EcPoint> m0_points_c2(num_ot);
  std::vector<yacl::crypto::EcPoint> m1_points_c1(num_ot);
  std::vector<yacl::crypto::EcPoint> m1_points_c2(num_ot);
  for (size_t i = 0; i < num_ot; ++i) {
    m0_points_c1[i] = m0s[i].GetC1();
    m0_points_c2[i] = m0s[i].GetC2();
    m1_points_c1[i] = m1s[i].GetC1();
    m1_points_c2[i] = m1s[i].GetC2();
  }
  auto send_future = std::async(std::launch::async, [&] {
    HomoOTESend(ctx, m0_points_c1, m1_points_c1, ec, other_party_rank);
  });
  send_future.get();
  auto send_future1 = std::async(std::launch::async, [&] {
    HomoOTESend(ctx, m0_points_c2, m1_points_c2, ec, other_party_rank);
  });
  send_future1.get();
}