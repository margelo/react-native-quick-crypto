package com.margelo.nitro.quickcrypto;

import android.util.Log;

// import androidx.annotation.Nullable;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfoProvider;
import com.facebook.react.TurboReactPackage;
import com.margelo.nitro.HybridObject;
import com.margelo.nitro.HybridObjectRegistry;

import java.util.HashMap;
// import java.util.function.Supplier;

public class QuickCryptoPackage extends TurboReactPackage {
  @Nullable
  @Override
  public NativeModule getModule(String name, ReactApplicationContext reactContext) {
    return null;
  }

  public QuickCryptoPackagePackage() {
      HybridObjectRegistry.registerHybridObjectConstructor("HybridRandom", () -> {
      Log.i("YEET", "initializing Random...");
      HybridObject obj = new HybridObject(new Random());
      Log.i("YEET", "done Random!");
      return f;
  }

  @Override
  public ReactModuleInfoProvider getReactModuleInfoProvider() {
    return () -> {
        return new HashMap<>();
    };
  }
}
