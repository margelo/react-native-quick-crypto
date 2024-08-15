#include <limits>

inline bool CheckIsUint32(double value) {
  return (value >= std::numeric_limits<uint32_t>::lowest() && value <= std::numeric_limits<uint32_t>::max());
}

inline bool CheckIsInt32(double value) {
  return (value >= std::numeric_limits<int32_t>::lowest() && value <= std::numeric_limits<int32_t>::max());
}