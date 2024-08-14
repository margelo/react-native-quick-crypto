#include <NitroModules/ArrayBuffer.hpp>
#include <cmath>
#include <future>

#include "HybridRandomSpec.hpp"
#include "utils/Utils.hpp"

namespace margelo::crypto {

using namespace margelo::nitro;
using namespace margelo::nitro::crypto;

class HybridRandom : public HybridRandomSpec {
public:
  std::future<std::shared_ptr<ArrayBuffer>> randomFill(const std::shared_ptr<ArrayBuffer>& buffer, double dOffset, double dSize) override;
  std::shared_ptr<ArrayBuffer> randomFillSync(const std::shared_ptr<ArrayBuffer>& buffer, double dOffset, double dSize) override;
};

inline size_t checkSize(double size) {
  if (!CheckIsUint32(size)) {
    throw std::runtime_error("size must be uint32");
  }
  if (static_cast<uint32_t>(size) > pow(2, 31) - 1) {
    throw std::runtime_error("size must be less than 2^31 - 1");
  }
  return static_cast<size_t>(size);
}

inline size_t checkOffset(double size, double offset) {
  if (!CheckIsUint32(offset)) {
    throw std::runtime_error("offset must be uint32");
  }
  if (offset > size) {
    throw std::runtime_error("offset must be less than size");
  }
  return static_cast<size_t>(offset);
}

} // namespace margelo::crypto
