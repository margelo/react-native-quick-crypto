package com.margelo.nitro.quickcrypto;

import android.util.Log;

import androidx.annotation.Nullable;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfoProvider;
import com.facebook.react.TurboReactPackage;

import java.util.HashMap;
import java.util.function.Supplier;

public class QuickCryptoPackage extends TurboReactPackage {
  private static final String TAG = "QuickCrypto";

  @Nullable
  @Override
  public NativeModule getModule(String name, ReactApplicationContext reactContext) {
    return null;
  }

  @Override
  public ReactModuleInfoProvider getReactModuleInfoProvider() {
    return () -> {
      return new HashMap<>();
    };
  }

  static {
    try {
      Log.i(TAG, "Loading C++ library...");
      System.loadLibrary(TAG);
      Log.i(TAG, "Successfully loaded C++ library!");
    } catch (Throwable e) {
      Log.e(TAG, "Failed to load C++ library! Is it properly installed and linked?", e);
      throw e;
    }
  }
}
