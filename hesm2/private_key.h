// Copyright 2024 Guowei Ling.
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

#include "examples/mpsu/hesm2/public_key.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace hesm2 {

class PrivateKey {
 public:
  explicit PrivateKey(std::shared_ptr<yacl::crypto::EcGroup> ec_group)
      : ec_group_(std::move(ec_group)),
        public_key_(ec_group_->GetGenerator(), ec_group_) {
    Initialize();
  }
  PrivateKey(std::shared_ptr<yacl::crypto::EcGroup> ec_group, size_t partynum)
      : ec_group_(std::move(ec_group)),
        public_key_(ec_group_->GetGenerator(), ec_group_) {
    Initialize(partynum);
  }

  const yacl::math::MPInt& GetK() const { return k_; }
  const yacl::math::MPInt& GetKi(size_t index) const { return ks_.at(index); }
  const PublicKey& GetPublicKey() const { return public_key_; }
  const PublicKey& GetPublicKeyi(size_t index) const {
    return public_keys_.at(index);
  }
  std::shared_ptr<yacl::crypto::EcGroup> GetEcGroup() const {
    return ec_group_;
  }

 private:
  void Initialize() {
    yacl::math::MPInt::RandomLtN(ec_group_->GetOrder(), &k_);
    public_key_ = GeneratePublicKey();
  }
  void Initialize(size_t partynum) {
    public_key_ = GenerateMasterPublicKey(partynum);
  }

  PublicKey GeneratePublicKey() const {
    auto generator = ec_group_->GetGenerator();
    auto point = ec_group_->Mul(generator, k_);
    return {point, ec_group_};
  }

  PublicKey GenerateMasterPublicKey(size_t partynum) {
    ks_.resize(partynum);
    auto generator = ec_group_->GetGenerator();
    for (size_t i = 0; i < partynum; ++i) {
      yacl::math::MPInt::RandomLtN(ec_group_->GetOrder(), &ks_[i]);
    }
    k_.Set(0);
    for (size_t i = 0; i < partynum; ++i) {
      k_ = k_.AddMod(ks_[i], ec_group_->GetOrder());
    }
    public_keys_.resize(partynum);
    for (size_t i = 0; i < partynum; ++i) {
      auto point = ec_group_->Mul(generator, ks_[i]);
      public_keys_.emplace_back(point, ec_group_);
    }
    auto point = ec_group_->Mul(generator, k_);
    return {point, ec_group_};
  }

  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  yacl::math::MPInt k_;
  std::vector<yacl::math::MPInt> ks_;
  PublicKey public_key_;
  std::vector<PublicKey> public_keys_;
};
}  // namespace hesm2