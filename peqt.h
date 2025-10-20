#pragma once

#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_split.h"
#include "fmt/format.h"
#include "libspu/core/config.h"
#include "libspu/device/io.h"
#include "libspu/kernel/hal/public_helper.h"
#include "libspu/kernel/hlo/basic_binary.h"
#include "libspu/kernel/hlo/casting.h"
#include "libspu/mpc/factory.h"
#include "libspu/spu.pb.h"
#include "xtensor/xadapt.hpp"
#include "xtensor/xio.hpp"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;
using yacl::link::Context;
using yacl::link::ContextDesc;

std::vector<int> ValueToBitVector(const spu::Value& val) {
  const auto& data = val.data();
  const int64_t numel = data.numel();
  const int64_t elsize = data.elsize();

  std::vector<int> result;
  result.reserve(numel);

  const uint8_t* raw_buf = reinterpret_cast<const uint8_t*>(data.buf()->data());
  for (int64_t i = 0; i < numel; ++i) {
    uint8_t byte = raw_buf[i * elsize];
    result.push_back(byte & 1);
  }
  return result;
}

std::vector<int> RunOnePartyEquality(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint64_t>& input, size_t rank) {
  spu::RuntimeConfig config;
  config.set_protocol(spu::ProtocolKind::SEMI2K);
  config.set_field(spu::FieldType::FM64);
  spu::populateRuntimeConfig(config);
  config.set_enable_action_trace(false);
  config.set_enable_type_checker(false);

  auto sctx = std::make_shared<spu::SPUContext>(config, ctx);
  spu::mpc::Factory::RegisterProtocol(sctx.get(), ctx);

  spu::device::ColocatedIo cio(sctx.get());
  xt::xarray<uint64_t> input_x = xt::adapt(input);
  cio.hostSetVar(fmt::format("input-{}", rank), input_x);
  cio.sync();

  auto a = cio.deviceGetVar("input-0");
  auto b = cio.deviceGetVar("input-1");
  auto eq = spu::kernel::hlo::Equal(sctx.get(), a, b);
  return ValueToBitVector(eq);
}
