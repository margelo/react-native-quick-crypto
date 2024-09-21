///
/// HybridPbkdf2Spec.cpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2024 Marc Rousavy @ Margelo
///

#include "HybridPbkdf2Spec.hpp"

namespace margelo::nitro::crypto {

  void HybridPbkdf2Spec::loadHybridMethods() {
    // load base methods/properties
    HybridObject::loadHybridMethods();
    // load custom methods/properties
    registerHybrids(this, [](Prototype& prototype) {
      prototype.registerHybridMethod("pbkdf2", &HybridPbkdf2Spec::pbkdf2);
      prototype.registerHybridMethod("pbkdf2Sync", &HybridPbkdf2Spec::pbkdf2Sync);
    });
  }

} // namespace margelo::nitro::crypto
