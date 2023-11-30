#ifndef MGL_JSIMACROS_H
#define MGL_JSIMACROS_H

#include <utility>

// Windows 8+ does not like abort() in Release mode
#ifdef _WIN32
#define ABORT_NO_BACKTRACE() _exit(134)
#else
#define ABORT_NO_BACKTRACE() abort()
#endif

struct AssertionInfo {
  const char *file_line;  // filename:line
  const char *message;
  const char *function;
};

inline void Abort() {
  //  DumpBacktrace(stderr);
  fflush(stderr);
  ABORT_NO_BACKTRACE();
}

inline void Assert(const AssertionInfo &info) {
  //  std::string name = GetHumanReadableProcessName();

  fprintf(stderr, "%s:%s%s Assertion `%s' failed.\n", info.file_line,
          info.function, *info.function ? ":" : "", info.message);
  fflush(stderr);

  Abort();
}

#define HOSTFN(name, basecount) \
    jsi::Function::createFromHostFunction( \
        rt, \
        jsi::PropNameID::forAscii(rt, name), \
        basecount, \
        [=](jsi::Runtime &rt, const jsi::Value &thisValue, const jsi::Value *args, size_t count) -> jsi::Value

#define HOST_LAMBDA(name, body) HOST_LAMBDA_CAP(name, [=], body)

#define HOST_LAMBDA_CAP(name, capture, body)                                 \
  std::make_pair(                                                            \
      name, capture(jsi::Runtime &runtime) {                                 \
        const auto func =                                                    \
            capture(jsi::Runtime & runtime, const jsi::Value &thisValue,     \
                    const jsi::Value *arguments, size_t count)               \
                ->jsi::Value body;                                           \
        auto propNameID = jsi::PropNameID::forAscii(runtime, name);          \
        return jsi::Function::createFromHostFunction(runtime, propNameID, 0, \
                                                     func);                  \
      })

#define JSI_VALUE(name, body) JSI_VALUE_CAP(name, [=], body)

#define JSI_VALUE_CAP(name, capture, body) \
  std::make_pair(name, capture(jsi::Runtime &runtime) body)

#define JSIF(capture)                                         \
  capture(jsi::Runtime &runtime, const jsi::Value &thisValue, \
          const jsi::Value *arguments, size_t count)          \
      ->jsi::Value

// Macros stolen from Node
#define ABORT() node::Abort()

#define ERROR_AND_ABORT(expr)                                                 \
  do {                                                                        \
    /* Make sure that this struct does not end up in inline code, but      */ \
    /* rather in a read-only data section when modifying this code.        */ \
    static const AssertionInfo args = {__FILE__ ":" STRINGIFY(__LINE__),      \
                                       #expr, PRETTY_FUNCTION_NAME};          \
    Assert(args);                                                             \
  } while (0)
#ifdef __GNUC__
#define LIKELY(expr) __builtin_expect(!!(expr), 1)
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define PRETTY_FUNCTION_NAME __PRETTY_FUNCTION__
#else
#define LIKELY(expr) expr
#define UNLIKELY(expr) expr
#define PRETTY_FUNCTION_NAME ""
#endif

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define CHECK(expr)          \
  do {                       \
    if (UNLIKELY(!(expr))) { \
      ERROR_AND_ABORT(expr); \
    }                        \
  } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))
#define CHECK_GE(a, b) CHECK((a) >= (b))
#define CHECK_GT(a, b) CHECK((a) > (b))
#define CHECK_LE(a, b) CHECK((a) <= (b))
#define CHECK_LT(a, b) CHECK((a) < (b))
#define CHECK_NE(a, b) CHECK((a) != (b))
#define CHECK_NULL(val) CHECK((val) == nullptr)
#define CHECK_NOT_NULL(val) CHECK((val) != nullptr)
#define CHECK_IMPLIES(a, b) CHECK(!(a) || (b))

#endif  // MGL_JSIMACROS_H
