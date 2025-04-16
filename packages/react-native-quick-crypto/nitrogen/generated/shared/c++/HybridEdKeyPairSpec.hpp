///
/// HybridEdKeyPairSpec.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#pragma once

#if __has_include(<NitroModules/HybridObject.hpp>)
#include <NitroModules/HybridObject.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif

// Forward declaration of `ArrayBuffer` to properly resolve imports.
namespace NitroModules { class ArrayBuffer; }

#include <NitroModules/Promise.hpp>
#include <optional>
#include <string>
#include <NitroModules/ArrayBuffer.hpp>

namespace margelo::nitro::crypto {

  using namespace margelo::nitro;

  /**
   * An abstract base class for `EdKeyPair`
   * Inherit this class to create instances of `HybridEdKeyPairSpec` in C++.
   * You must explicitly call `HybridObject`'s constructor yourself, because it is virtual.
   * @example
   * ```cpp
   * class HybridEdKeyPair: public HybridEdKeyPairSpec {
   * public:
   *   HybridEdKeyPair(...): HybridObject(TAG) { ... }
   *   // ...
   * };
   * ```
   */
  class HybridEdKeyPairSpec: public virtual HybridObject {
    public:
      // Constructor
      explicit HybridEdKeyPairSpec(): HybridObject(TAG) { }

      // Destructor
      ~HybridEdKeyPairSpec() override = default;

    public:
      // Properties
      

    public:
      // Methods
      virtual std::shared_ptr<Promise<void>> generateKeyPair(double publicFormat, double publicType, double privateFormat, double privateType, const std::optional<std::string>& cipher, const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) = 0;
      virtual void generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType, const std::optional<std::string>& cipher, const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) = 0;
      virtual std::shared_ptr<ArrayBuffer> getPublicKey() = 0;
      virtual std::shared_ptr<ArrayBuffer> getPrivateKey() = 0;
      virtual std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> sign(const std::shared_ptr<ArrayBuffer>& message, const std::optional<std::shared_ptr<ArrayBuffer>>& key) = 0;
      virtual std::shared_ptr<ArrayBuffer> signSync(const std::shared_ptr<ArrayBuffer>& message, const std::optional<std::shared_ptr<ArrayBuffer>>& key) = 0;
      virtual std::shared_ptr<Promise<bool>> verify(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message, const std::optional<std::shared_ptr<ArrayBuffer>>& key) = 0;
      virtual bool verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message, const std::optional<std::shared_ptr<ArrayBuffer>>& key) = 0;
      virtual void setCurve(const std::string& curve) = 0;

    protected:
      // Hybrid Setup
      void loadHybridMethods() override;

    protected:
      // Tag for logging
      static constexpr auto TAG = "EdKeyPair";
  };

} // namespace margelo::nitro::crypto
