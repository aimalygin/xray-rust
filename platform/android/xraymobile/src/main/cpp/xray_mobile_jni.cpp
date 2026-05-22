#include <jni.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "xray_ffi.h"

namespace {

struct AndroidSocketProtector {
  JavaVM *vm = nullptr;
  jobject object = nullptr;
  jmethodID protect_method = nullptr;

  ~AndroidSocketProtector() {
    if (vm == nullptr || object == nullptr) {
      return;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_OK &&
        env != nullptr) {
      env->DeleteGlobalRef(object);
    }
  }
};

struct NativeCore {
  XrayCoreHandle *core = nullptr;
  std::unique_ptr<AndroidSocketProtector> protector;

  ~NativeCore() {
    if (core != nullptr) {
      xray_core_free(core);
      core = nullptr;
    }
  }
};

NativeCore *core_from_handle(jlong handle) {
  return reinterpret_cast<NativeCore *>(handle);
}

std::string error_message(XrayError *error) {
  if (error == nullptr) {
    return "xray operation failed";
  }

  const char *message = xray_error_message(error);
  if (message == nullptr) {
    return "xray operation failed";
  }

  return std::string(message);
}

void throw_core_exception(JNIEnv *env, XrayStatus status, XrayError *error) {
  jclass exception_class = env->FindClass("org/xrayrust/mobile/XrayCoreException");
  if (exception_class == nullptr) {
    xray_error_free(error);
    return;
  }

  jmethodID constructor =
      env->GetMethodID(exception_class, "<init>", "(ILjava/lang/String;)V");
  if (constructor == nullptr) {
    xray_error_free(error);
    return;
  }

  jstring message = env->NewStringUTF(error_message(error).c_str());
  jobject exception = env->NewObject(
      exception_class,
      constructor,
      static_cast<jint>(status),
      message);
  env->Throw(reinterpret_cast<jthrowable>(exception));
  xray_error_free(error);
}

bool check_status(JNIEnv *env, XrayStatus status, XrayError *error) {
  if (status == XRAY_STATUS_OK) {
    xray_error_free(error);
    return true;
  }

  throw_core_exception(env, status, error);
  return false;
}

jbyteArray bytes_to_array(JNIEnv *env, const uint8_t *bytes, size_t len) {
  jbyteArray array = env->NewByteArray(static_cast<jsize>(len));
  if (array == nullptr) {
    return nullptr;
  }

  env->SetByteArrayRegion(
      array,
      0,
      static_cast<jsize>(len),
      reinterpret_cast<const jbyte *>(bytes));
  return array;
}

int32_t protect_socket(int32_t fd, void *user_data) {
  auto *protector = reinterpret_cast<AndroidSocketProtector *>(user_data);
  if (protector == nullptr || protector->vm == nullptr || protector->object == nullptr) {
    return 0;
  }

  JNIEnv *env = nullptr;
  bool attached = false;
  jint env_status =
      protector->vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
  if (env_status == JNI_EDETACHED) {
    if (protector->vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
      return 0;
    }
    attached = true;
  } else if (env_status != JNI_OK) {
    return 0;
  }

  const jboolean protected_socket =
      env->CallBooleanMethod(protector->object, protector->protect_method, fd);
  const bool has_exception = env->ExceptionCheck();

  if (attached) {
    protector->vm->DetachCurrentThread();
  }

  return !has_exception && protected_socket == JNI_TRUE ? 1 : 0;
}

} // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeNew(JNIEnv *env, jclass) {
  XrayError *error = nullptr;
  XrayCoreHandle *core = xray_core_new(&error);
  if (core == nullptr) {
    throw_core_exception(env, xray_error_code(error), error);
    return 0;
  }

  auto native = std::make_unique<NativeCore>();
  native->core = core;
  return reinterpret_cast<jlong>(native.release());
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeLoadConfig(
    JNIEnv *env,
    jobject,
    jlong handle,
    jstring config_json) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  const char *raw = env->GetStringUTFChars(config_json, nullptr);
  if (raw == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_load_config_json(native->core, raw, &error);
  env->ReleaseStringUTFChars(config_json, raw);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetSocketProtector(
    JNIEnv *env,
    jobject,
    jlong handle,
    jobject protector_object) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  auto protector = std::make_unique<AndroidSocketProtector>();
  env->GetJavaVM(&protector->vm);
  protector->object = env->NewGlobalRef(protector_object);
  jclass protector_class = env->GetObjectClass(protector_object);
  protector->protect_method = env->GetMethodID(protector_class, "protect", "(I)Z");
  if (protector->protect_method == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_socket_protect_callback(
      native->core,
      protect_socket,
      protector.get(),
      &error);
  if (check_status(env, status, error)) {
    native->protector = std::move(protector);
  }
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeStart(JNIEnv *env, jobject, jlong handle) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_start(native->core, &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeStop(JNIEnv *env, jobject, jlong handle) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_stop(native->core, &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeFree(JNIEnv *, jobject, jlong handle) {
  delete core_from_handle(handle);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativePushPacket(
    JNIEnv *env,
    jobject,
    jlong handle,
    jbyteArray packet) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  const jsize len = env->GetArrayLength(packet);
  jbyte *bytes = env->GetByteArrayElements(packet, nullptr);
  if (bytes == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_tun_push_packet(
      native->core,
      reinterpret_cast<const uint8_t *>(bytes),
      static_cast<size_t>(len),
      &error);
  env->ReleaseByteArrayElements(packet, bytes, JNI_ABORT);
  check_status(env, status, error);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_org_xrayrust_mobile_XrayCore_nativePollPacket(
    JNIEnv *env,
    jobject,
    jlong handle,
    jint max_bytes) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr || max_bytes <= 0) {
    return nullptr;
  }

  std::string buffer(static_cast<size_t>(max_bytes), '\0');
  size_t written = 0;
  XrayError *error = nullptr;
  XrayStatus status = xray_tun_poll_packet(
      native->core,
      reinterpret_cast<uint8_t *>(buffer.data()),
      buffer.size(),
      &written,
      &error);
  if (status == XRAY_STATUS_NO_PACKET) {
    xray_error_free(error);
    return nullptr;
  }
  if (!check_status(env, status, error)) {
    return nullptr;
  }

  return bytes_to_array(
      env,
      reinterpret_cast<const uint8_t *>(buffer.data()),
      written);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeStats(JNIEnv *env, jobject, jlong handle) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return nullptr;
  }

  XrayTunStats stats = {};
  XrayError *error = nullptr;
  XrayStatus status = xray_tun_stats(native->core, &stats, &error);
  if (!check_status(env, status, error)) {
    return nullptr;
  }

  jlong values[3] = {
      static_cast<jlong>(stats.inbound_packets),
      static_cast<jlong>(stats.outbound_packets),
      static_cast<jlong>(stats.dropped_packets),
  };
  jlongArray array = env->NewLongArray(3);
  env->SetLongArrayRegion(array, 0, 3, values);
  return array;
}
