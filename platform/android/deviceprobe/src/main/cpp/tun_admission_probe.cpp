// Bounded device-only regression probe for Android per-app VPN bypass (#51).
#include <jni.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
struct Socket {
  int fd;
  ~Socket() { if (fd >= 0) close(fd); }
};
}

extern "C" JNIEXPORT jintArray JNICALL
Java_org_xrayrust_deviceprobe_AdmissionProbeActivity_nativeProbe(
    JNIEnv *env, jobject, jstring address, jint port, jboolean udp, jstring device) {
  jint result[3] = {0, 0, 0}; // bind errno, I/O errno, verified echo bytes
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_port = htons(static_cast<uint16_t>(port));
  const char *host = env->GetStringUTFChars(address, nullptr);
  if (host == nullptr) return nullptr;
  const bool valid = port > 0 && port <= 65535 && inet_pton(AF_INET, host, &target.sin_addr) == 1;
  env->ReleaseStringUTFChars(address, host);
  Socket socket{valid ? ::socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0) : -1};
  if (socket.fd < 0) result[1] = valid ? errno : EINVAL;
  if (socket.fd >= 0 && device != nullptr) {
    const char *name = env->GetStringUTFChars(device, nullptr);
    if (name == nullptr) return nullptr;
    const size_t length = std::strlen(name);
    if (length == 0 || length >= IFNAMSIZ) result[0] = EINVAL;
    else if (setsockopt(socket.fd, SOL_SOCKET, SO_BINDTODEVICE, name, length + 1) != 0) result[0] = errno;
    env->ReleaseStringUTFChars(device, name);
  }
  if (socket.fd >= 0 && result[0] == 0) {
    fcntl(socket.fd, F_SETFL, O_NONBLOCK);
    int connected = connect(socket.fd, reinterpret_cast<sockaddr *>(&target), sizeof(target));
    if (connected != 0 && errno == EINPROGRESS) {
      pollfd wait{socket.fd, POLLOUT, 0};
      if (poll(&wait, 1, 3000) <= 0) result[1] = ETIMEDOUT;
      else { socklen_t size = sizeof(result[1]); getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &result[1], &size); }
    } else if (connected != 0) result[1] = errno;
    if (result[1] == 0) {
      constexpr char payload[] = "xray-tun-admission-device-probe";
      constexpr size_t size = sizeof(payload) - 1;
      if (send(socket.fd, payload, size, MSG_NOSIGNAL) != static_cast<ssize_t>(size)) result[1] = errno ? errno : EIO;
      else {
        char data[size];
        size_t received = 0;
        while (received < size) {
          pollfd wait{socket.fd, POLLIN, 0};
          if (poll(&wait, 1, 1500) <= 0) { result[1] = ETIMEDOUT; break; }
          const ssize_t n = recv(socket.fd, data + received, size - received, 0);
          if (n <= 0) { result[1] = n == 0 ? ECONNRESET : errno; break; }
          received += static_cast<size_t>(n);
          if (udp) break;
        }
        if (result[1] == 0 && received == size && std::memcmp(data, payload, size) == 0) result[2] = size;
        else if (result[1] == 0) result[1] = EPROTO;
      }
    }
  }
  jintArray output = env->NewIntArray(3);
  if (output != nullptr) env->SetIntArrayRegion(output, 0, 3, result);
  return output;
}
