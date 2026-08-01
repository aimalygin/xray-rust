#include <jni.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "xray_ffi.h"

namespace {

constexpr uint32_t kExpectedFfiMajorVersion = 1;

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
  std::mutex poll_mutex;
  std::vector<size_t> poll_lengths;
  std::vector<jint> java_poll_lengths;

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

void throw_illegal_argument(JNIEnv *env, const char *message) {
  jclass exception_class = env->FindClass("java/lang/IllegalArgumentException");
  if (exception_class != nullptr) {
    env->ThrowNew(exception_class, message);
  }
}

bool ensure_supported_ffi_abi(JNIEnv *env) {
  const uint32_t actual = xray_ffi_version_major();
  if (actual == kExpectedFfiMajorVersion) {
    return true;
  }

  jclass exception_class = env->FindClass("java/lang/IllegalStateException");
  if (exception_class != nullptr) {
    const std::string message =
        "incompatible xray FFI ABI major: expected " +
        std::to_string(kExpectedFfiMajorVersion) + ", got " +
        std::to_string(actual);
    env->ThrowNew(exception_class, message.c_str());
  }
  return false;
}

void append_utf8(std::string *output, uint32_t code_point) {
  if (code_point <= 0x7F) {
    output->push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7FF) {
    output->push_back(static_cast<char>(0xC0 | (code_point >> 6)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  } else if (code_point <= 0xFFFF) {
    output->push_back(static_cast<char>(0xE0 | (code_point >> 12)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  } else {
    output->push_back(static_cast<char>(0xF0 | (code_point >> 18)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
  }
}

bool jstring_to_utf8(JNIEnv *env, jstring value, std::string *output) {
  if (value == nullptr) {
    throw_illegal_argument(env, "string must not be null");
    return false;
  }
  const jsize length = env->GetStringLength(value);
  const jchar *characters = env->GetStringChars(value, nullptr);
  if (characters == nullptr) {
    return false;
  }

  output->clear();
  output->reserve(static_cast<size_t>(length));
  for (jsize index = 0; index < length; ++index) {
    uint32_t code_point = characters[index];
    if (code_point == 0) {
      env->ReleaseStringChars(value, characters);
      throw_illegal_argument(env, "embedded NUL is not supported by the C ABI");
      return false;
    }
    if (code_point >= 0xD800 && code_point <= 0xDBFF) {
      if (index + 1 < length) {
        const uint32_t low = characters[index + 1];
        if (low >= 0xDC00 && low <= 0xDFFF) {
          code_point =
              0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00);
          ++index;
        } else {
          code_point = 0xFFFD;
        }
      } else {
        code_point = 0xFFFD;
      }
    } else if (code_point >= 0xDC00 && code_point <= 0xDFFF) {
      code_point = 0xFFFD;
    }
    append_utf8(output, code_point);
  }
  env->ReleaseStringChars(value, characters);
  return true;
}

jstring utf8_to_jstring(JNIEnv *env, std::string_view value) {
  std::vector<jchar> characters;
  characters.reserve(value.size());
  size_t index = 0;
  while (index < value.size()) {
    const uint8_t first = static_cast<uint8_t>(value[index]);
    uint32_t code_point = 0xFFFD;
    size_t sequence_length = 1;
    if (first <= 0x7F) {
      code_point = first;
    } else if ((first & 0xE0) == 0xC0 && index + 1 < value.size()) {
      const uint8_t second = static_cast<uint8_t>(value[index + 1]);
      const uint32_t candidate = ((first & 0x1F) << 6) | (second & 0x3F);
      if ((second & 0xC0) == 0x80 && candidate >= 0x80) {
        code_point = candidate;
        sequence_length = 2;
      }
    } else if ((first & 0xF0) == 0xE0 && index + 2 < value.size()) {
      const uint8_t second = static_cast<uint8_t>(value[index + 1]);
      const uint8_t third = static_cast<uint8_t>(value[index + 2]);
      const uint32_t candidate =
          ((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F);
      if ((second & 0xC0) == 0x80 && (third & 0xC0) == 0x80 &&
          candidate >= 0x800 && !(candidate >= 0xD800 && candidate <= 0xDFFF)) {
        code_point = candidate;
        sequence_length = 3;
      }
    } else if ((first & 0xF8) == 0xF0 && index + 3 < value.size()) {
      const uint8_t second = static_cast<uint8_t>(value[index + 1]);
      const uint8_t third = static_cast<uint8_t>(value[index + 2]);
      const uint8_t fourth = static_cast<uint8_t>(value[index + 3]);
      const uint32_t candidate =
          ((first & 0x07) << 18) | ((second & 0x3F) << 12) |
          ((third & 0x3F) << 6) | (fourth & 0x3F);
      if ((second & 0xC0) == 0x80 && (third & 0xC0) == 0x80 &&
          (fourth & 0xC0) == 0x80 && candidate >= 0x10000 &&
          candidate <= 0x10FFFF) {
        code_point = candidate;
        sequence_length = 4;
      }
    }
    index += sequence_length;

    if (code_point <= 0xFFFF) {
      characters.push_back(static_cast<jchar>(code_point));
    } else {
      code_point -= 0x10000;
      characters.push_back(static_cast<jchar>(0xD800 | (code_point >> 10)));
      characters.push_back(static_cast<jchar>(0xDC00 | (code_point & 0x3FF)));
    }
  }
  const jchar empty = 0;
  return env->NewString(
      characters.empty() ? &empty : characters.data(),
      static_cast<jsize>(characters.size()));
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

  jstring message = utf8_to_jstring(env, error_message(error));
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
  if (has_exception) {
    env->ExceptionClear();
  }

  if (attached) {
    protector->vm->DetachCurrentThread();
  }

  return !has_exception && protected_socket == JNI_TRUE ? 1 : 0;
}

} // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeNew(JNIEnv *env, jclass) {
  if (!ensure_supported_ffi_abi(env)) {
    return 0;
  }

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

  std::string utf8_config;
  if (!jstring_to_utf8(env, config_json, &utf8_config)) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status =
      xray_core_load_config_json(native->core, utf8_config.c_str(), &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeConfigWarnings(
    JNIEnv *env,
    jobject,
    jlong handle) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return nullptr;
  }

  size_t required = 0;
  XrayError *error = nullptr;
  XrayStatus status =
      xray_core_config_warnings(native->core, nullptr, 0, &required, &error);
  if (status == XRAY_STATUS_BUFFER_TOO_SMALL) {
    xray_error_free(error);
    error = nullptr;
  } else if (!check_status(env, status, error)) {
    return nullptr;
  }
  if (required == 0) {
    return nullptr;
  }

  std::vector<char> buffer(required + 1, '\0');
  size_t written = 0;
  status = xray_core_config_warnings(
      native->core,
      buffer.data(),
      buffer.size(),
      &written,
      &error);
  if (!check_status(env, status, error)) {
    return nullptr;
  }
  if (written > required) {
    throw_illegal_argument(env, "xray returned an invalid warnings length");
    return nullptr;
  }
  return utf8_to_jstring(env, std::string_view(buffer.data(), written));
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
Java_org_xrayrust_mobile_XrayCore_nativeSetStartupProbe(
    JNIEnv *env,
    jobject,
    jlong handle,
    jstring url,
    jlong timeout_ms,
    jstring outbound_tag) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  std::string utf8_url;
  if (!jstring_to_utf8(env, url, &utf8_url)) {
    return;
  }

  std::string utf8_outbound_tag;
  const char *raw_outbound_tag = nullptr;
  if (outbound_tag != nullptr) {
    if (!jstring_to_utf8(env, outbound_tag, &utf8_outbound_tag)) {
      return;
    }
    raw_outbound_tag = utf8_outbound_tag.c_str();
  }

  const uint64_t ffi_timeout_ms =
      timeout_ms > 0 ? static_cast<uint64_t>(timeout_ms) : 0;
  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_startup_probe(
      native->core,
      utf8_url.c_str(),
      ffi_timeout_ms,
      raw_outbound_tag,
      &error);

  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetTunFd(
    JNIEnv *env,
    jobject,
    jlong handle,
    jint fd,
    jint packet_format,
    jint close_policy) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_tun_fd(
      native->core,
      static_cast<int32_t>(fd),
      static_cast<int32_t>(packet_format),
      static_cast<int32_t>(close_policy),
      &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetTunRuntimeProfile(
    JNIEnv *env,
    jobject,
    jlong handle,
    jint profile) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_tun_runtime_profile(
      native->core,
      static_cast<int32_t>(profile),
      &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetTunCollectTcpTimings(
    JNIEnv *env,
    jobject,
    jlong handle,
    jboolean collect) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_tun_collect_tcp_timings(
      native->core,
      collect == JNI_TRUE ? 1 : 0,
      &error);
  check_status(env, status, error);
}

extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetDnsBootstrapMode(
    JNIEnv *env,
    jobject,
    jlong handle,
    jint mode) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_dns_bootstrap_mode(
      native->core,
      static_cast<int32_t>(mode),
      &error);
  check_status(env, status, error);
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
    jbyteArray packet,
    jint length) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }
  if (packet == nullptr) {
    throw_illegal_argument(env, "packet must not be null");
    return;
  }

  const jsize array_length = env->GetArrayLength(packet);
  if (length < 0 || length > array_length) {
    throw_illegal_argument(env, "packet length is outside the source array");
    return;
  }
  jbyte *bytes = env->GetByteArrayElements(packet, nullptr);
  if (bytes == nullptr) {
    return;
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_tun_push_packet(
      native->core,
      reinterpret_cast<const uint8_t *>(bytes),
      static_cast<size_t>(length),
      &error);
  env->ReleaseByteArrayElements(packet, bytes, JNI_ABORT);
  check_status(env, status, error);
}

extern "C" JNIEXPORT jint JNICALL
Java_org_xrayrust_mobile_XrayCore_nativePollPackets(
    JNIEnv *env,
    jobject,
    jlong handle,
    jobject storage,
    jintArray lengths,
    jint max_packet_bytes,
    jint wait_milliseconds) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return 0;
  }
  if (storage == nullptr || lengths == nullptr || max_packet_bytes <= 0 ||
      wait_milliseconds < 0) {
    throw_illegal_argument(env, "invalid packet poll arguments");
    return 0;
  }
  auto *buffer =
      static_cast<uint8_t *>(env->GetDirectBufferAddress(storage));
  const jlong buffer_capacity = env->GetDirectBufferCapacity(storage);
  const jsize max_packets = env->GetArrayLength(lengths);
  if (buffer == nullptr || buffer_capacity <= 0 || max_packets <= 0) {
    throw_illegal_argument(env, "packet storage must be a non-empty direct buffer");
    return 0;
  }
  const uint64_t required_capacity =
      static_cast<uint64_t>(max_packets) *
      static_cast<uint64_t>(max_packet_bytes);
  if (required_capacity > static_cast<uint64_t>(buffer_capacity)) {
    throw_illegal_argument(env, "packet storage is too small");
    return 0;
  }

  std::lock_guard<std::mutex> guard(native->poll_mutex);
  native->poll_lengths.resize(static_cast<size_t>(max_packets));
  size_t packet_count = 0;
  XrayError *error = nullptr;
  XrayStatus status = xray_tun_poll_packets(
      native->core,
      buffer,
      static_cast<size_t>(buffer_capacity),
      native->poll_lengths.data(),
      static_cast<size_t>(max_packets),
      &packet_count,
      static_cast<uint32_t>(wait_milliseconds),
      &error);
  if (status == XRAY_STATUS_NO_PACKET) {
    xray_error_free(error);
    return 0;
  }
  if (!check_status(env, status, error)) {
    return 0;
  }
  if (packet_count > static_cast<size_t>(max_packets)) {
    throw_illegal_argument(env, "xray returned an invalid packet count");
    return 0;
  }

  native->java_poll_lengths.resize(packet_count);
  size_t total_length = 0;
  for (size_t index = 0; index < packet_count; ++index) {
    const size_t packet_length = native->poll_lengths[index];
    if (packet_length > static_cast<size_t>(max_packet_bytes) ||
        packet_length > static_cast<size_t>(std::numeric_limits<jint>::max()) ||
        total_length > static_cast<size_t>(buffer_capacity) - packet_length) {
      throw_illegal_argument(env, "xray returned invalid packet lengths");
      return 0;
    }
    native->java_poll_lengths[index] = static_cast<jint>(packet_length);
    total_length += packet_length;
  }
  if (packet_count > 0) {
    env->SetIntArrayRegion(
        lengths,
        0,
        static_cast<jsize>(packet_count),
        native->java_poll_lengths.data());
  }
  return static_cast<jint>(packet_count);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeStats(JNIEnv *env, jobject, jlong handle) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return nullptr;
  }

  XrayTunStats stats = {};
  stats.struct_size = sizeof(XrayTunStats);
  XrayError *error = nullptr;
  XrayStatus status = xray_tun_stats(native->core, &stats, &error);
  if (!check_status(env, status, error)) {
    return nullptr;
  }

  jlong values[19] = {
      static_cast<jlong>(stats.inbound_packets),
      static_cast<jlong>(stats.outbound_packets),
      static_cast<jlong>(stats.dropped_packets),
      static_cast<jlong>(stats.udp_remote_open_events),
      static_cast<jlong>(stats.udp_remote_udp443_open_events),
      static_cast<jlong>(stats.udp_remote_written_bytes),
      static_cast<jlong>(stats.udp_remote_read_bytes),
      static_cast<jlong>(stats.tcp_open_events),
      static_cast<jlong>(stats.tcp_open_duration_ms_total),
      static_cast<jlong>(stats.tcp_open_duration_ms_max),
      static_cast<jlong>(stats.tcp_first_byte_events),
      static_cast<jlong>(stats.tcp_first_byte_duration_ms_total),
      static_cast<jlong>(stats.tcp_first_byte_duration_ms_max),
      static_cast<jlong>(stats.tcp443_open_events),
      static_cast<jlong>(stats.tcp443_open_duration_ms_total),
      static_cast<jlong>(stats.tcp443_open_duration_ms_max),
      static_cast<jlong>(stats.tcp443_first_byte_events),
      static_cast<jlong>(stats.tcp443_first_byte_duration_ms_total),
      static_cast<jlong>(stats.tcp443_first_byte_duration_ms_max),
  };
  jlongArray array = env->NewLongArray(19);
  env->SetLongArrayRegion(array, 0, 19, values);
  return array;
}
