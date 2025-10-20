#pragma once

#include <cstddef>
#include <ostream>
#include <random>
#include <vector>

#include "examples/mpsu/hesm2/ahesm2.h"
#include "examples/mpsu/hesm2/ciphertext.h"
#include "examples/mpsu/hesm2/private_key.h"
#include "examples/mpsu/ote.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

inline std::vector<size_t> GenShuffledRangeWithYacl(size_t n) {
  std::vector<size_t> perm(n);
  for (size_t i = 0; i < n; ++i) {
    perm[i] = i;
  }
  auto rng = []() {
    return static_cast<uint32_t>(yacl::crypto::SecureRandU128());
  };
  std::shuffle(perm.begin(), perm.end(), std::mt19937(rng()));
  return perm;
}

inline std::vector<hesm2::Ciphertext> ShuffleWithYacl(
    std::vector<hesm2::Ciphertext> &ciphertexts,
    const std::vector<size_t> &perm) {
  size_t n = ciphertexts.size();
  YACL_ENFORCE(perm.size() == n, "Permutation size must match input size");
  std::vector<hesm2::Ciphertext> output(n);
  for (size_t i = 0; i < n; ++i) {
    output[i] = ciphertexts[perm[i]];
  }
  return output;
}

inline std::vector<hesm2::Ciphertext> RerandomizeCiphertextsWithYacl(
    const std::vector<hesm2::Ciphertext> &ciphertexts,
    const hesm2::PublicKey &pk) {
  size_t n = ciphertexts.size();
  std::vector<hesm2::Ciphertext> output(n);
  std::vector<hesm2::Ciphertext> rerandomized_ciphertexts(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      output[i] = hesm2::ReRand(ciphertexts[i], pk);
    }
  });
  return output;
}

void CiphertextstoBuffer(absl::Span<hesm2::Ciphertext> in,
                         absl::Span<std::uint8_t> buffer,
                         std::shared_ptr<yacl::crypto::EcGroup> ec) {
  uint64_t point_size = ec->GetSerializeLength();
  YACL_ENFORCE(buffer.size() == in.size() * 2 * point_size,
               "buffer size mismatch: got {}, need {}", buffer.size(),
               in.size() * 2 * point_size);

  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * point_size * 2;
      auto c1 = in[idx].GetC1();
      auto c2 = in[idx].GetC2();
      ec->SerializePoint(c1, buffer.data() + offset, point_size);
      ec->SerializePoint(c2, buffer.data() + offset + point_size, point_size);
    }
  });
}

void BuffertoCiphertexts(absl::Span<hesm2::Ciphertext> in,
                         absl::Span<std::uint8_t> buffer,
                         std::shared_ptr<yacl::crypto::EcGroup> ec) {
  uint64_t point_size = ec->GetSerializeLength();
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto c1 = ec->DeserializePoint(
          absl::MakeSpan(buffer.data() + idx * 2 * point_size, point_size));
      auto c2 = ec->DeserializePoint(absl::MakeSpan(
          buffer.data() + (idx * 2 + 1) * point_size, point_size));
      in[idx] = hesm2::Ciphertext{c1, c2};
    }
  });
}

std::vector<int32_t> ShuffleAndDecP1(
    const std::shared_ptr<yacl::link::Context> &ctx,
    std::vector<hesm2::Ciphertext> &ciphertexts, const yacl::math::MPInt &k,
    const std::shared_ptr<yacl::crypto::EcGroup> &ec,
    const hesm2::PublicKey &pk) {
  size_t num_cipher = ciphertexts.size();
  // rerandomize
  size_t partynum = ctx->WorldSize();
  std::vector<hesm2::Ciphertext> reciphertexts =
      RerandomizeCiphertextsWithYacl(ciphertexts, pk);
  std::vector<size_t> perm = GenShuffledRangeWithYacl(num_cipher);
  std::vector<hesm2::Ciphertext> shuffled_ciphertexts =
      ShuffleWithYacl(reciphertexts, perm);

  // send
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * 2 * num_cipher;
  std::vector<uint8_t> buffer(total_length);
  CiphertextstoBuffer(absl::MakeSpan(shuffled_ciphertexts),
                      absl::MakeSpan(buffer), ec);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(buffer.data(), buffer.size() * sizeof(uint8_t)),
      "Send shuffled ciphertexts");

  // recv
  auto revbytes = ctx->Recv(ctx->PrevRank(), "Receive shuffled messages");

  std::memcpy(buffer.data(), revbytes.data(), revbytes.size());
  BuffertoCiphertexts(absl::MakeSpan(shuffled_ciphertexts),
                      absl::MakeSpan(buffer), ec);

  perm = GenShuffledRangeWithYacl(num_cipher);
  std::vector<hesm2::Ciphertext> newshuffled_ciphertexts(num_cipher);
  newshuffled_ciphertexts = ShuffleWithYacl(shuffled_ciphertexts, perm);

  std::vector<yacl::crypto::EcPoint> c1_points(num_cipher);
  std::vector<yacl::crypto::EcPoint> c2_points(num_cipher);
  yacl::parallel_for(0, num_cipher, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      c1_points[i] = newshuffled_ciphertexts[i].GetC1();
      c2_points[i] = newshuffled_ciphertexts[i].GetC2();
    }
  });

  size_t total_length_c1 = point_size * num_cipher;
  std::vector<uint8_t> buffer_c1(total_length_c1);
  PointstoBuffer(absl::MakeSpan(c1_points), absl::MakeSpan(buffer_c1), ec);

  for (size_t i = 1; i < partynum; i++) {
    ctx->SendAsync(i,
                   yacl::ByteContainerView(buffer_c1.data(),
                                           buffer_c1.size() * sizeof(uint8_t)),
                   "Send c1 points for decryption");
  }

  std::vector<yacl::crypto::EcPoint> c1_points_rev(num_cipher);
  for (size_t i = 1; i < partynum; i++) {
    auto revbytes = ctx->Recv(i, "Receive decrypted c1 points");
    std::vector<uint8_t> c1_skbuffer(total_length_c1);
    std::memcpy(c1_skbuffer.data(), revbytes.data(), revbytes.size());
    BuffertoPoints(absl::MakeSpan(c1_points_rev), absl::MakeSpan(c1_skbuffer),
                   ec);
    yacl::parallel_for(0, num_cipher, [&](size_t begin, size_t end) {
      for (size_t j = begin; j < end; ++j) {
        c2_points[j] = ec->Sub(c2_points[j], c1_points_rev[j]);
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
  std::vector<int32_t> messages(num_cipher);
  yacl::parallel_for(0, num_cipher, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      hesm2::DecryptResult dec_res =
          hesm2::DecryptforInt(final_ciphertexts[i], ec, k);
      YACL_ENFORCE(dec_res.success, "Decryption failed at index {}", i);
      messages[i] = dec_res.m.Get<int32_t>();
    }
  });

  return messages;
}

void ShuffleAndDecPi(const std::shared_ptr<yacl::link::Context> &ctx,
                     const yacl::math::MPInt &k,
                     const std::shared_ptr<yacl::crypto::EcGroup> &ec,
                     size_t cipher_num) {
  // recv
  uint64_t point_size = ec->GetSerializeLength();
  size_t total_length = point_size * 2 * cipher_num;
  std::vector<uint8_t> buffer(total_length);
  auto revbytes = ctx->Recv(ctx->PrevRank(), "Receive shuffled ciphertexts");
  std::memcpy(buffer.data(), revbytes.data(), revbytes.size());
  std::vector<hesm2::Ciphertext> shuffled_ciphertexts(cipher_num);
  BuffertoCiphertexts(absl::MakeSpan(shuffled_ciphertexts),
                      absl::MakeSpan(buffer), ec);

  // shuffle
  std::vector<size_t> perm = GenShuffledRangeWithYacl(cipher_num);
  std::vector<hesm2::Ciphertext> descrambled_ciphertexts =
      ShuffleWithYacl(shuffled_ciphertexts, perm);
  // send
  CiphertextstoBuffer(absl::MakeSpan(descrambled_ciphertexts),
                      absl::MakeSpan(buffer), ec);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(buffer.data(), buffer.size() * sizeof(uint8_t)),
      "Send descrambled ciphertexts");

  size_t total_length_c1 = point_size * cipher_num;
  std::vector<uint8_t> buffer_c1(total_length_c1);
  auto c1bytes = ctx->Recv(0, "Receive c1 points for decryption");
  std::memcpy(buffer_c1.data(), c1bytes.data(), c1bytes.size());

  std::vector<yacl::crypto::EcPoint> c1_points(cipher_num);
  std::vector<yacl::crypto::EcPoint> c1_points_sk(cipher_num);
  BuffertoPoints(absl::MakeSpan(c1_points), absl::MakeSpan(buffer_c1), ec);
  yacl::parallel_for(0, cipher_num, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      c1_points_sk[i] = ec->Mul(c1_points[i], k);
    }
  });
  PointstoBuffer(absl::MakeSpan(c1_points_sk), absl::MakeSpan(buffer_c1), ec);
  ctx->SendAsync(0,
                 yacl::ByteContainerView(buffer_c1.data(),
                                         buffer_c1.size() * sizeof(uint8_t)),
                 "Send decrypted c1 points");
}