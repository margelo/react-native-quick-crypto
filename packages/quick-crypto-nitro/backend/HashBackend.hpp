#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct evp_md_ctx_st;

namespace margelo::quickcrypto {

class __attribute__((visibility("default"))) HashBackend final {
 public:
  explicit HashBackend(const std::string& algorithm);
  void update(const uint8_t* data, size_t length);
  std::vector<uint8_t> digest();

 private:
  std::unique_ptr<evp_md_ctx_st, void (*)(evp_md_ctx_st*)> context;
};

} // namespace margelo::quickcrypto
