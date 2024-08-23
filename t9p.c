
#include <getopt.h>
#include <sys/socket.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define PACKED __attribute__((packed))
#else
#error Unsupported compiler
#endif

#define COMMON_FIELDS \
    uint32_t size; \
    uint8_t type; \
    uint16_t tag;


typedef struct PACKED qid_s {
    uint8_t type;
    uint32_t version;
    uint64_t path;
} qid_t;

struct PACKED TRcommon {
    COMMON_FIELDS
};

struct PACKED Tversion {
    COMMON_FIELDS
    uint32_t msize;
    uint16_t version_len;
    uint8_t version[];
};

struct PACKED Rversion {
    COMMON_FIELDS
    uint32_t msize;
    uint16_t version_len;
    uint8_t version[];
};

struct PACKED Tauth {
    COMMON_FIELDS
    uint32_t afid;
    uint16_t uname_len;
    uint8_t uname[];
    /* uint16_t aname_len; */
    /* uint8_t aname[]; */
};

struct PACKED Rauth {
    COMMON_FIELDS
    qid_t aqid;
};

struct PACKED Rerror {
    COMMON_FIELDS
    uint16_t ename_len;
    uint8_t ename[];
};

struct PACKED Rlerror {
    COMMON_FIELDS
    uint32_t ecode;
};

struct PACKED Tflush {
    COMMON_FIELDS
    uint16_t oldtag;
};

struct PACKED Rflush {
    COMMON_FIELDS
};

struct PACKED Tattach {
    COMMON_FIELDS
    uint32_t fid;
    uint32_t afid;
    uint16_t uname_len;
    uint8_t uname[];
    /* uint16_t aname_len; */
    /* uint8_t aname[]; */
};

struct PACKED Rattached {
    COMMON_FIELDS
    qid_t qid;
};

struct PACKED Topen {
    COMMON_FIELDS
    uint32_t fid;
    uint8_t mode;
};

struct PACKED Ropen {
    COMMON_FIELDS
    qid_t qid;
    uint32_t iounit;
};

struct PACKED Tcreate {
    COMMON_FIELDS
    uint32_t fid;
    uint16_t name_len;
    uint16_t name[];
    /* uint32_t perm; */
    /* uint8_t mode */
};

struct PACKED Rcreate {
    COMMON_FIELDS
    qid_t qid;
    uint32_t iounit;
};

struct PACKED Tread {
    COMMON_FIELDS
    uint32_t fid;
    uint64_t offset;
    uint32_t count;
};

struct PACKED Rread {
    COMMON_FIELDS
    uint32_t count;
    uint8_t data[];
};

struct PACKED Tclunk {
    COMMON_FIELDS
    uint32_t fid;
};

struct PACKED Rclunk {
    COMMON_FIELDS
};

struct PACKED Tremove {
    COMMON_FIELDS
    uint32_t fid;
};

struct PACKED Rremove {
    COMMON_FIELDS
};

struct PACKED Tstat {
    COMMON_FIELDS
    uint32_t fid;
};

struct PACKED Rstat {
    COMMON_FIELDS
    uint16_t stat_len;
    uint8_t stat[];
};

struct PACKED Twstat {
    COMMON_FIELDS
    uint32_t fid;
    uint16_t stat_len;
    uint8_t stat[];
};

struct PACKED Trstat {
    COMMON_FIELDS
};


int main(int argc, char** argv) {

}