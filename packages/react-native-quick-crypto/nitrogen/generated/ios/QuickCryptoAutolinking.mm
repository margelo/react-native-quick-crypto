///
/// QuickCryptoAutolinking.mm
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#import <Foundation/Foundation.h>
#import <NitroModules/HybridObjectRegistry.hpp>

#import <type_traits>

#include "HybridCipher.hpp"
#include "HybridCipherFactory.hpp"
#include "HybridEdKeyPair.hpp"
#include "HybridHash.hpp"
#include "HybridHmac.hpp"
#include "HybridPbkdf2.hpp"
#include "HybridRandom.hpp"

@interface QuickCryptoAutolinking : NSObject
@end

@implementation QuickCryptoAutolinking

+ (void) load {
  using namespace margelo::nitro;
  using namespace margelo::nitro::crypto;

  HybridObjectRegistry::registerHybridObjectConstructor(
    "Cipher",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridCipher>,
                    "The HybridObject \"HybridCipher\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridCipher>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "CipherFactory",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridCipherFactory>,
                    "The HybridObject \"HybridCipherFactory\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridCipherFactory>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "EdKeyPair",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridEdKeyPair>,
                    "The HybridObject \"HybridEdKeyPair\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridEdKeyPair>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "Hash",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridHash>,
                    "The HybridObject \"HybridHash\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridHash>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "Hmac",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridHmac>,
                    "The HybridObject \"HybridHmac\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridHmac>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "Pbkdf2",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridPbkdf2>,
                    "The HybridObject \"HybridPbkdf2\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridPbkdf2>();
    }
  );
  HybridObjectRegistry::registerHybridObjectConstructor(
    "Random",
    []() -> std::shared_ptr<HybridObject> {
      static_assert(std::is_default_constructible_v<HybridRandom>,
                    "The HybridObject \"HybridRandom\" is not default-constructible! "
                    "Create a public constructor that takes zero arguments to be able to autolink this HybridObject.");
      return std::make_shared<HybridRandom>();
    }
  );
}

@end
