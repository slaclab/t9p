/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: 9P/2000.L serialization library
 * ----------------------------------------------------------------------------
 * This file is part of 't9p'. It is subject to the license terms in the
 * LICENSE.txt file found in the top-level directory of this distribution,
 * and at:
 *    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html.
 * No part of 't9p', including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 * ----------------------------------------------------------------------------
 **/
#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#undef T9P_PACKED
#define T9P_PACKED __attribute__((packed))
#else
#error Unsupported compiler
#endif

struct t9p_stat;
struct t9p_setattr;

#define T9P_NOTAG (~(uint16_t)0)
#define T9P_NOFID (~(uint32_t)0)
#define T9P_NOUID (~(uint32_t)0)

enum
{
  T9P_TYPE_Rlerror = 7,
  T9P_TYPE_Tstatfs = 8,
  T9P_TYPE_Rstatfs,
  T9P_TYPE_Tlopen = 12,
  T9P_TYPE_Rlopen,
  T9P_TYPE_Tlcreate = 14,
  T9P_TYPE_Rlcreate,
  T9P_TYPE_Tsymlink = 16,
  T9P_TYPE_Rsymlink,
	T9P_TYPE_Tmknod = 18,
	T9P_TYPE_Rmknod,
	T9P_TYPE_Trename = 20,
	T9P_TYPE_Rrename,
  T9P_TYPE_Treadlink = 22,
  T9P_TYPE_Rreadlink,
  T9P_TYPE_Tgetattr = 24,
  T9P_TYPE_Rgetattr,
  T9P_TYPE_Tsetattr = 26,
  T9P_TYPE_Rsetattr,
  T9P_TYPE_Treaddir = 40,
  T9P_TYPE_Rreaddir,
  T9P_TYPE_Tfsync = 50,
  T9P_TYPE_Rfsync,
  T9P_TYPE_Tlock = 52,
  T9P_TYPE_Rlock,
  T9P_TYPE_Tgetlock = 54,
  T9P_TYPE_Rgetlock,
  T9P_TYPE_Tlink = 70,
  T9P_TYPE_Rlink,
  T9P_TYPE_Tmkdir = 72,
  T9P_TYPE_Rmkdir,
  T9P_TYPE_Trenameat = 74,
  T9P_TYPE_Rrenameat,
  T9P_TYPE_Tunlinkat = 76,
  T9P_TYPE_Runlinkat,
  T9P_TYPE_Tversion = 100,
  T9P_TYPE_Rversion,
  T9P_TYPE_Tauth = 102,
  T9P_TYPE_Rauth,
  T9P_TYPE_Tattach = 104,
  T9P_TYPE_Rattach,
  T9P_TYPE_Terror = 106,
  T9P_TYPE_Rerror,
  T9P_TYPE_Tflush = 108,
  T9P_TYPE_Rflush,
  T9P_TYPE_Twalk = 110,
  T9P_TYPE_Rwalk,
  T9P_TYPE_Topen = 112,
  T9P_TYPE_Ropen,
  T9P_TYPE_Tcreate = 114,
  T9P_TYPE_Rcreate,
  T9P_TYPE_Tread = 116,
  T9P_TYPE_Rread,
  T9P_TYPE_Twrite = 118,
  T9P_TYPE_Rwrite,
  T9P_TYPE_Tclunk = 120,
  T9P_TYPE_Rclunk,
  T9P_TYPE_Tremove = 122,
  T9P_TYPE_Rremove,
  T9P_TYPE_Tstat = 124,
  T9P_TYPE_Rstat,
  T9P_TYPE_Twstat = 126,
  T9P_TYPE_Rwstat,
  T9P_TYPE_Tmax,
};

const char* t9p_type_string(int type);

#define T9P_COMMON_FIELDS                                                                          \
  uint32_t size;                                                                                   \
  uint8_t type;                                                                                    \
  uint16_t tag;

typedef struct T9P_PACKED qid_s
{
  uint8_t type;
  uint32_t version;
  uint64_t path;
} qid_t;

struct T9P_PACKED TRcommon{T9P_COMMON_FIELDS};

int decode_TRcommon(struct TRcommon* com, const void* buf, size_t len);

struct T9P_PACKED Tversion
{
  T9P_COMMON_FIELDS
  uint32_t msize;
  uint16_t version_len;
  uint8_t version[];
};

int encode_Tversion(
  void* pout, size_t outsize, uint16_t tag, uint32_t msize, uint16_t version_len,
  const uint8_t* version
);

struct T9P_PACKED Rversion
{
  T9P_COMMON_FIELDS
  uint32_t msize;
  uint16_t version_len;
  uint8_t version[];
};

int decode_Rversion(struct Rversion** out, const void* buf, size_t buflen);

struct T9P_PACKED Tauth
{
  T9P_COMMON_FIELDS
  uint32_t afid;
  uint16_t uname_len;
  uint8_t uname[];
  /* uint16_t aname_len; */
  /* uint8_t aname[]; */
};

struct T9P_PACKED Rauth
{
  T9P_COMMON_FIELDS
  qid_t aqid;
};

struct T9P_PACKED Rerror
{
  T9P_COMMON_FIELDS
  uint16_t ename_len;
  uint8_t ename[];
};

struct T9P_PACKED Rlerror
{
  T9P_COMMON_FIELDS
  uint32_t ecode;
};

int decode_Rlerror(struct Rlerror* rl, const void* buf, size_t len);

struct T9P_PACKED Tflush
{
  T9P_COMMON_FIELDS
  uint16_t oldtag;
};

struct T9P_PACKED Rflush{T9P_COMMON_FIELDS};

struct T9P_PACKED Tattach
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint32_t afid;
  uint16_t uname_len;
  uint8_t uname[];
  /* uint16_t aname_len; */
  /* uint8_t aname[]; */
  /* uint32_t uid */
};

int encode_Tattach(
  void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t afid, uint16_t uname_len,
  const uint8_t* uname, uint16_t aname_len, const uint8_t* aname, uint32_t uid
);

struct T9P_PACKED Rattach
{
  T9P_COMMON_FIELDS
  qid_t qid;
};

int decode_Rattach(struct Rattach* out, const void* buf, size_t buflen);

struct T9P_PACKED Topen
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint8_t mode;
};

struct T9P_PACKED Ropen
{
  T9P_COMMON_FIELDS
  qid_t qid;
  uint32_t iounit;
};

struct T9P_PACKED Tlopen
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint32_t flags;
};

int encode_Tlopen(void* buf, size_t outusize, uint16_t tag, uint32_t fid, uint32_t flags);

struct T9P_PACKED Rlopen
{
  T9P_COMMON_FIELDS
  qid_t qid;
  uint32_t iounit;
};

int decode_Rlopen(struct Rlopen* out, const void* buf, size_t buflen);

struct T9P_PACKED Tcreate
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint16_t name_len;
  uint16_t name[];
  /* uint32_t perm; */
  /* uint8_t mode */
};

struct T9P_PACKED Rcreate
{
  T9P_COMMON_FIELDS
  qid_t qid;
  uint32_t iounit;
};

struct T9P_PACKED Tread
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint64_t offset;
  uint32_t count;
};

int encode_Tread(
  void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count
);

struct T9P_PACKED Rread
{
  T9P_COMMON_FIELDS
  uint32_t count;
  uint8_t data[];
};

int decode_Rread(struct Rread* out, const void* buf, size_t buflen);

struct T9P_PACKED Tclunk
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Tclunk(void* buf, size_t outsize, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rclunk{T9P_COMMON_FIELDS};

struct T9P_PACKED Tremove
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Tremove(void* buf, size_t outsize, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rremove{T9P_COMMON_FIELDS};

struct T9P_PACKED Tstat
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Tstat(void* buf, size_t bufsize, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rstat
{
  T9P_COMMON_FIELDS
  uint16_t stat_len;
  uint8_t stat[];
};

struct T9P_PACKED Twstat
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint16_t stat_len;
  uint8_t stat[];
};

struct T9P_PACKED Trstat{T9P_COMMON_FIELDS};

struct T9P_PACKED Twalk
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint32_t newfid;
  uint16_t nwname;
  /*nwname*(wname[s])*/
};

int encode_Twalk(
  void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t newfid, uint16_t nwnamecount,
  const char* const* names
);

struct T9P_PACKED Rwalk
{
  T9P_COMMON_FIELDS
  uint16_t nwqid;
  /*nwqid*(qid[13])*/
};

int decode_Rwalk(struct Rwalk* rw, const void* buf, size_t outsize, qid_t** outqids);

struct T9P_PACKED Tgetattr
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint64_t request_mask;
};

int encode_Tgetattr(void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t request_mask);

struct T9P_PACKED Rgetattr
{
  T9P_COMMON_FIELDS
  uint64_t valid;
  qid_t qid;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t nlink;
  uint64_t rdev;
  uint64_t fsize;
  uint64_t blksize;
  uint64_t blocks;
  uint64_t atime_sec;
  uint64_t atime_nsec;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
  uint64_t ctime_sec;
  uint64_t ctime_nsec;
  uint64_t btime_sec;
  uint64_t btime_nsec;
  uint64_t gen;
  uint64_t data_version;
};

int decode_Rgetattr(struct Rgetattr* attr, const void* buf, size_t bufsize);

struct T9P_PACKED Twrite
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint64_t offset;
  uint32_t count;
  char data[];
};

/** Encodes the start of a Twrite message. Does not encode the data part */
int encode_Twrite(
  void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count
);

struct T9P_PACKED Rwrite
{
  T9P_COMMON_FIELDS
  uint32_t count;
};

int decode_Rwrite(struct Rwrite* out, const void* buf, size_t len);

struct T9P_PACKED Tstatfs
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Tstatfs(void* buf, size_t buflen, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rstatfs
{
  T9P_COMMON_FIELDS
  uint32_t ftype;
  uint32_t bsize;
  uint64_t blocks;
  uint64_t bfree;
  uint64_t bavail;
  uint64_t files;
  uint64_t ffree;
  uint64_t fsid;
  uint32_t namelen;
};

int decode_Rstatfs(struct Rstatfs* st, const void* buf, size_t buflen);

struct T9P_PACKED Tlcreate
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint16_t namelen;
  char name[];
  /*flags[4]*/
  /*mode[4]*/
  /*gid[4]*/
};

int encode_Tlcreate(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, const char* name, uint32_t flags,
  uint32_t mode, uint32_t gid
);

struct T9P_PACKED Rlcreate
{
  T9P_COMMON_FIELDS
  qid_t qid;
  uint32_t iounit;
};

int decode_Rlcreate(struct Rlcreate* rl, const void* buf, size_t buflen);

struct T9P_PACKED Tfsync
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Tfsync(void* buf, size_t buflen, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rfsync{T9P_COMMON_FIELDS};

int decode_Rfsync(struct Rfsync* rf, const void* buf, size_t buflen);

struct T9P_PACKED Tmkdir
{
  T9P_COMMON_FIELDS
  uint32_t dfid;
  /*char name[s]*/
  /*uint32_t mode*/
  /*uint32_t gid*/
};

int encode_Tmkdir(
  void* buf, size_t buflen, uint16_t tag, uint32_t dfid, const char* name, uint32_t mode,
  uint32_t gid
);

struct T9P_PACKED Rmkdir
{
  T9P_COMMON_FIELDS
  qid_t qid;
};

int decode_Rmkdir(struct Rmkdir* rm, const void* buf, size_t buflen);

struct T9P_PACKED Treadlink
{
  T9P_COMMON_FIELDS
  uint32_t fid;
};

int encode_Treadlink(void* buf, size_t buflen, uint16_t tag, uint32_t fid);

struct T9P_PACKED Rreadlink
{
  T9P_COMMON_FIELDS
  uint16_t plen;
#ifdef _T9P_PROTO_IMPL
  char path[]; /**< This field is not what you expect */
#endif
};

int decode_Rreadlink(
  struct Rreadlink* rl, char* linkPath, size_t linkPathSize, const void* buf, size_t buflen
);

int encode_Tsymlink(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, const char* dst, const char* src,
  uint32_t gid
);

struct T9P_PACKED Rsymlink
{
  T9P_COMMON_FIELDS
  qid_t qid;
};

int decode_Rsymlink(struct Rsymlink* rs, const void* buf, size_t buflen);

struct T9P_PACKED Treaddir
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint64_t offset;
  uint32_t count;
};

int encode_Treaddir(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count
);

/** Single directory entry */
struct T9P_PACKED Rreaddir_dir
{
  qid_t qid;
  uint64_t offset;
  uint8_t type;
  uint16_t namelen;
  char name[]; /**< NOT null terminated */
};

struct T9P_PACKED Rreaddir
{
  T9P_COMMON_FIELDS
  uint32_t count;
  /*struct Rreaddir_dir dirs[]*/
};

/**
 * Unlike other encode/decode functions, this one uses a callback pattern to avoid unnecessary
 * memory allocations.
 */
int decode_Rreaddir(
  struct Rreaddir* rd, const void* buf, size_t buflen,
  void (*parse_dir_callback)(void*, struct Rreaddir_dir, const char*), void* param
);

struct T9P_PACKED Tunlinkat
{
  T9P_COMMON_FIELDS
  uint32_t dirfd;
  /*uint16_t namelen;*/
  /*char name[];*/
  /*uint32_t flags*/ /* Why is this after the name? Really? */
};

int encode_Tunlinkat(
  void* buf, size_t buflen, uint16_t tag, uint32_t dfid, const char* name, uint32_t flags
);

struct T9P_PACKED Runlinkat{T9P_COMMON_FIELDS};

int decode_Runlinkat(struct Runlinkat* ru, const void* buf, size_t buflen);

struct T9P_PACKED Trenameat
{
  T9P_COMMON_FIELDS
  uint32_t olddirfd;
  uint16_t oldnamelen;
  char oldname[];
  /*uint32_t newdirfid*/
  /*newname[s]*/
};

int encode_Trenameat(
  void* buf, size_t buflen, uint16_t tag, uint32_t olddirfd, const char* oldname, uint32_t newdirfd,
  const char* newname
);

struct T9P_PACKED Rrenameat{T9P_COMMON_FIELDS};

int decode_Rrenameat(struct Rrenameat* ra, const void* buf, size_t buflen);

struct T9P_PACKED Tsetattr
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint32_t valid;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t fsize;
  uint64_t atime_sec;
  uint64_t atime_nsec;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
};

int encode_Tsetattr(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint32_t valid,
  const struct t9p_setattr* attr
);

struct T9P_PACKED Rsetattr{T9P_COMMON_FIELDS};

int decode_Rsetattr(struct Rsetattr* rs, const void* buf, size_t buflen);

struct T9P_PACKED Tlink
{
  T9P_COMMON_FIELDS
  uint32_t dfid;
  uint32_t fid;
  uint16_t namelen;
  char name[];
};

int encode_Tlink(void* buf, size_t buflen, uint16_t tag, uint32_t dfid,
  uint32_t fid, const char* name);

struct Rlink
{
  T9P_COMMON_FIELDS
};

int decode_Rlink(struct Rlink* rl, const void* buf, size_t buflen);

struct T9P_PACKED Trename
{
  T9P_COMMON_FIELDS
  uint32_t fid;
  uint32_t dfid;
  uint16_t namelen;
  char name[];
};

int encode_Trename(void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint32_t dfid,
  const char* name);

struct Rrename
{
  T9P_COMMON_FIELDS
};

int decode_Rrename(struct Rrename* rn, const void* buf, size_t buflen);