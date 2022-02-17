package com.reactnativefastcrypto;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = FastCryptoModule.NAME)
public class FastCryptoModule extends ReactContextBaseJavaModule {
  public static final String NAME = "FastCrypto";

  public FastCryptoModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @NonNull
  @Override
  public String getName() {
    return NAME;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public boolean install() {
    try {
      Log.i(NAME, "Loading C++ library...");
      System.loadLibrary("reactnativefastcrypto");

      JavaScriptContextHolder jsContext = getReactApplicationContext().getJavaScriptContextHolder();

      Log.i(NAME, "Installing JSI Bindings for react-native-fast-crypto...");
      nativeInstall(jsContext.get(), rootDirectory);
      Log.i(NAME, "Successfully installed JSI Bindings for react-native-fast-crypto!");

      return true;
    } catch (Exception exception) {
      Log.e(NAME, "Failed to install JSI Bindings for react-native-fast-crypto!", exception);
      return false;
    }
  }

  private static native void nativeInstall(long jsiPtr, String path);
}
