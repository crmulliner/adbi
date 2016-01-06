#include <sys/types.h>

extern ssize_t my_recv(int socket, void *buffer, size_t length, int flags);

ssize_t my_recv_arm(int socket, void *buffer, size_t length, int flags) {
  return my_recv(socket, buffer, length, flags);
}
