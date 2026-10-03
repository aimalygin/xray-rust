// Diagnostic libc entry-point counts, NOT timings or an exhaustive syscall trace.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <limits.h>
#define OPS 16
#define STRIDE 16
#define WORDS (8+OPS*STRIDE)
static _Atomic(uint64_t) *map;
__attribute__((constructor)) static void begin(void) {
    const char *path=getenv("XRAY_CENSUS_MAP"); if (!path) return;
    int fd=open(path,O_RDWR|O_CREAT|O_EXCL,0600); if(fd<0) _exit(121);
    if(ftruncate(fd,WORDS*8)!=0) _exit(122);
    void *p=mmap(NULL,WORDS*8,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);close(fd);
    if(p==MAP_FAILED) _exit(123);
    map=p;map[0]=0x58524159434e5331ULL;map[1]=1;map[2]=getpid();map[3]=OPS;map[4]=STRIDE;
}
static void record(unsigned op,size_t requested,ssize_t result,int err) {
    if(!map)return;
    _Atomic(uint64_t) *v=map+8+op*STRIDE;
    atomic_fetch_add_explicit(v,1,memory_order_relaxed);
    atomic_fetch_add_explicit(v+1,requested,memory_order_relaxed);
    if(result<0){ atomic_fetch_add_explicit(v+((err==EAGAIN||err==EWOULDBLOCK)?3:4),1,memory_order_relaxed);return; }
    atomic_fetch_add_explicit(v+2,(uint64_t)result,memory_order_relaxed);
    if(result==0)atomic_fetch_add_explicit(v+5,1,memory_order_relaxed);
    uint64_t bounds[]={0,1024,2048,4096,8192,16384,32768,65536,131072};unsigned b=0;
    while(b<9&&(uint64_t)result>bounds[b])b++;
    atomic_fetch_add_explicit(v+6+b,1,memory_order_relaxed);
}
#define INTERPOSE(repl,orig) __attribute__((used)) static struct{const void *replacement;const void *original;} i_##orig __attribute__((section("__DATA,__interpose")))={(const void *)(uintptr_t)&repl,(const void *)(uintptr_t)&orig};
#define DONE(op,n,call) ssize_t rc=(call);int err=errno;record(op,n,rc,err);errno=err;return rc
static ssize_t c_read(int fd,void*b,size_t n){DONE(0,n,read(fd,b,n));} INTERPOSE(c_read,read)
static ssize_t c_write(int fd,const void*b,size_t n){DONE(1,n,write(fd,b,n));} INTERPOSE(c_write,write)
static ssize_t c_recv(int fd,void*b,size_t n,int f){DONE(2,n,recv(fd,b,n,f));} INTERPOSE(c_recv,recv)
static ssize_t c_send(int fd,const void*b,size_t n,int f){DONE(3,n,send(fd,b,n,f));} INTERPOSE(c_send,send)
static ssize_t c_recvfrom(int fd,void*b,size_t n,int f,struct sockaddr*a,socklen_t*l){DONE(4,n,recvfrom(fd,b,n,f,a,l));} INTERPOSE(c_recvfrom,recvfrom)
static ssize_t c_sendto(int fd,const void*b,size_t n,int f,const struct sockaddr*a,socklen_t l){DONE(5,n,sendto(fd,b,n,f,a,l));} INTERPOSE(c_sendto,sendto)
static size_t iovbytes(const struct iovec*v,int n){size_t s=0;for(int i=0;i<n;i++)s+=v[i].iov_len;return s;}
static ssize_t c_readv(int fd,const struct iovec*v,int n){DONE(6,iovbytes(v,n),readv(fd,v,n));} INTERPOSE(c_readv,readv)
static ssize_t c_writev(int fd,const struct iovec*v,int n){for(int i=0;i<n;i++)record(13,v[i].iov_len,(ssize_t)v[i].iov_len,0);record(14,n,n,0);DONE(7,iovbytes(v,n),writev(fd,v,n));} INTERPOSE(c_writev,writev)
static ssize_t c_recvmsg(int fd,struct msghdr*m,int f){DONE(8,iovbytes(m->msg_iov,m->msg_iovlen),recvmsg(fd,m,f));} INTERPOSE(c_recvmsg,recvmsg)
static ssize_t c_sendmsg(int fd,const struct msghdr*m,int f){DONE(9,iovbytes(m->msg_iov,m->msg_iovlen),sendmsg(fd,m,f));} INTERPOSE(c_sendmsg,sendmsg)
static int c_entropy(void*b,size_t n){int rc=getentropy(b,n);int err=errno;record(10,n,rc==0?(ssize_t)n:-1,err);errno=err;return rc;} INTERPOSE(c_entropy,getentropy)
static int c_kevent(int k,const struct kevent*c,int n,struct kevent*e,int ne,const struct timespec*t){int rc=kevent(k,c,n,e,ne,t);int err=errno;record(11,0,rc,err);errno=err;return rc;} INTERPOSE(c_kevent,kevent)
static int c_kevent64(int k,const struct kevent64_s*c,int n,struct kevent64_s*e,int ne,unsigned f,const struct timespec*t){int rc=kevent64(k,c,n,e,ne,f,t);int err=errno;record(12,0,rc,err);errno=err;return rc;} INTERPOSE(c_kevent64,kevent64)

static void c_arc4random(void*b,size_t n){arc4random_buf(b,n);int err=errno;record(15,n,(ssize_t)n,err);errno=err;} INTERPOSE(c_arc4random,arc4random_buf)
