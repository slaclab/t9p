/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: 9P/2000.L serialization library. Handles encoding and decoding
 *  of messages to a binary format that can be sent over the wire. Messages are
 *  byteswapped to account for LE/BE differences. 9P itself is a little-endian
 *  format, so on most platforms byteswapping is not necessary.
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
#define _T9P_PROTO_IMPL

#include "t9proto.h"
#include "t9p.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if __RTEMS_MAJOR__ < 5
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#define bswap_16(x) __builtin_bswap16(x)
#else
#include <endian.h>
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#define BSWAP32(x) bswap_32(x)
#define BSWAP16(x) bswap_16(x)
#define BSWAP64(x) bswap_64(x)
#else
#define BSWAP32(x) (uint32_t)(x)
#define BSWAP16(x) (uint16_t)(x)
#define BSWAP64(x) (uint64_t)(x)
#endif

static qid_t
swapqid(qid_t in)
{
  qid_t q = {
    .path = BSWAP64(in.path),
    .type = in.type,
    .version = BSWAP32(in.version)
  };
  return q;
}

static void
wr64(uint8_t** pos, uint64_t val)
{
  *(uint64_t*)(*pos) = BSWAP64(val);
  *pos += 8;
}

static void
wr8(uint8_t** pos, uint8_t val)
{
  **(pos) = val;
  *pos += 1;
}

static void
wr32(uint8_t** pos, uint32_t val)
{
  *(uint32_t*)(*pos) = BSWAP32(val);
  *pos += 4;
}

static void
wr16(uint8_t** pos, uint16_t val)
{
  *(uint16_t*)(*pos) = BSWAP16(val);
  *pos += 2;
}

static void
wrbuf(uint8_t** pos, const uint8_t* buf, uint32_t bl)
{
  for (uint32_t n = 0; n < bl; ++n)
    *(*pos)++ = buf[n];
}

static void
wrstr(uint8_t** pos, const char* str, int len)
{
  len = len < 0 ? strlen(str) : len;
  wr16(pos, len);
  wrbuf(pos, (const uint8_t*)str, len);
}

const char*
t9p_type_string(int type)
{
  switch (type) {
  case T9P_TYPE_Rlerror:
    return "Rlerror";
  case T9P_TYPE_Tlopen:
    return "Tlopen";
  case T9P_TYPE_Rlopen:
    return "Rlopen";
  case T9P_TYPE_Tlcreate:
    return "Tlcreate";
  case T9P_TYPE_Rlcreate:
    return "Rlcreate";
  case T9P_TYPE_Tgetattr:
    return "Tgetattr";
  case T9P_TYPE_Rgetattr:
    return "Rgetattr";
  case T9P_TYPE_Tversion:
    return "Tversion";
  case T9P_TYPE_Rversion:
    return "Rversion";
  case T9P_TYPE_Tauth:
    return "Tauth";
  case T9P_TYPE_Rauth:
    return "Rauth";
  case T9P_TYPE_Tattach:
    return "Tattach";
  case T9P_TYPE_Rattach:
    return "Rattach";
  case T9P_TYPE_Terror:
    return "Terror";
  case T9P_TYPE_Rerror:
    return "Rerror";
  case T9P_TYPE_Tflush:
    return "Tflush";
  case T9P_TYPE_Rflush:
    return "Rflush";
  case T9P_TYPE_Twalk:
    return "Twalk";
  case T9P_TYPE_Rwalk:
    return "Rwalk";
  case T9P_TYPE_Topen:
    return "Topen";
  case T9P_TYPE_Ropen:
    return "Ropen";
  case T9P_TYPE_Tcreate:
    return "Tcreate";
  case T9P_TYPE_Rcreate:
    return "Rcreate";
  case T9P_TYPE_Tread:
    return "Tread";
  case T9P_TYPE_Rread:
    return "Rread";
  case T9P_TYPE_Twrite:
    return "Twrite";
  case T9P_TYPE_Rwrite:
    return "Rwrite";
  case T9P_TYPE_Tclunk:
    return "Tclunk";
  case T9P_TYPE_Rclunk:
    return "Rclunk";
  case T9P_TYPE_Tremove:
    return "Tremove";
  case T9P_TYPE_Rremove:
    return "Rremove";
  case T9P_TYPE_Tstat:
    return "Tstat";
  case T9P_TYPE_Rstat:
    return "Rstat";
  case T9P_TYPE_Twstat:
    return "Twstat";
  case T9P_TYPE_Rwstat:
    return "Rwstat";
  case T9P_TYPE_Tstatfs:
    return "Tstatfs";
  case T9P_TYPE_Rstatfs:
    return "Rstatfs";
  case T9P_TYPE_Treadlink:
    return "Treadlink";
  case T9P_TYPE_Rreadlink:
    return "Rreadlink";
  case T9P_TYPE_Tsymlink:
    return "Tsymlink";
  case T9P_TYPE_Rsymlink:
    return "Rsymlink";
  case T9P_TYPE_Rreaddir:
    return "Rreaddir";
  case T9P_TYPE_Treaddir:
    return "Treaddir";
  case T9P_TYPE_Tmknod:
    return "Tmknod";
  case T9P_TYPE_Rmknod:
    return "Rmknod";
  case T9P_TYPE_Trename:
    return "Trename";
  case T9P_TYPE_Rrename:
    return "Rrename";
  case T9P_TYPE_Tlink:
    return "Tlink";
  case T9P_TYPE_Rlink:
    return "Rlink";
  default:
    assert(0);
    return NULL;
  }
}

int
encode_Tversion(
  void* pout, size_t outsize, uint16_t tag, uint32_t msize, uint16_t version_len,
  const uint8_t* version
)
{
  const int totalsz = sizeof(struct Tversion) + version_len;
  if (outsize < totalsz) {
    return -1;
  }

  struct Tversion* tv = pout;
  tv->size = BSWAP32(totalsz);
  tv->msize = BSWAP32(msize);
  tv->type = T9P_TYPE_Tversion;
  tv->tag = BSWAP16(tag);
  tv->version_len = BSWAP16(version_len);
  memcpy(tv->version, version, version_len);
  return totalsz;
}

int
decode_Rversion(struct Rversion** out, const void* buf, size_t buflen)
{
  const struct Rversion* in = buf;
  if (buflen < sizeof(struct Rversion))
    return -1;

  uint32_t len = BSWAP32(in->size);
  *out = malloc(len);
  memcpy(*out, buf, len);
  (*out)->msize = BSWAP32(in->msize);
  (*out)->size = BSWAP32(in->size);
  (*out)->tag = BSWAP16(in->tag);
  (*out)->type = in->type;
  (*out)->version_len = BSWAP32(in->version_len);
  return len;
}

int
encode_Tattach(
  void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t afid, uint16_t uname_len,
  const uint8_t* uname, uint16_t aname_len, const uint8_t* aname, uint32_t uid
)
{
  const int totalsz = sizeof(struct Tattach) + uname_len + sizeof(uint16_t) /*aname_len*/ +
                      aname_len + sizeof(uint32_t) /*uid*/;
  if (outsize < totalsz) {
    return -1;
  }

  struct Tattach* ta = buf;
  ta->size = BSWAP32(totalsz);
  ta->type = T9P_TYPE_Tattach;
  ta->tag = BSWAP16(tag);

  ta->fid = BSWAP32(fid);
  ta->afid = BSWAP32(afid);
  ta->uname_len = BSWAP16(uname_len);

  uint8_t* b = ((uint8_t*)buf) + offsetof(struct Tattach, uname);
  wrbuf(&b, uname, uname_len);
  wr16(&b, aname_len);
  wrbuf(&b, aname, aname_len);
  wr32(&b, uid);
  return totalsz;
}

int
decode_Rattach(struct Rattach* out, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*out))
    return -1;

  *out = *(struct Rattach*)buf;
  out->size = BSWAP32(out->size);
  out->tag = BSWAP16(out->tag);
  out->qid = swapqid(out->qid);
  return sizeof(*out);
}

int
encode_Tclunk(void* buf, size_t outsize, uint16_t tag, uint32_t fid)
{
  if (outsize < sizeof(struct Tclunk))
    return -1;

  struct Tclunk* tc = buf;
  tc->size = BSWAP32(sizeof(*tc));
  tc->fid = BSWAP32(fid);
  tc->type = T9P_TYPE_Tclunk;
  tc->tag = BSWAP16(tag);

  return sizeof(*tc);
}

int
encode_Tlopen(void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t flags)
{
  if (outsize < sizeof(struct Tlopen))
    return -1;

  struct Tlopen* tl = buf;
  tl->fid = BSWAP32(fid);
  tl->flags = BSWAP32(flags);
  tl->size = BSWAP32(sizeof(*tl));
  tl->tag = BSWAP16(tag);
  tl->type = T9P_TYPE_Tlopen;

  return sizeof(*tl);
}

int
decode_Rlopen(struct Rlopen* out, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*out))
    return -1;

  const struct Rlopen* rl = buf;
  out->iounit = BSWAP32(rl->iounit);
  out->size = BSWAP32(rl->size);
  out->tag = BSWAP16(rl->tag);
  out->qid = swapqid(rl->qid);
  out->type = rl->type;
  return sizeof(*rl);
}

int
decode_Rwalk(struct Rwalk* rw, const void* buf, size_t buflen, qid_t** outqids)
{
  if (buflen < sizeof(struct Rwalk))
    return -1;

  *rw = *(struct Rwalk*)buf;
  rw->size = BSWAP32(rw->size);
  rw->tag = BSWAP16(rw->tag);
  rw->nwqid = BSWAP16(rw->nwqid);
  const qid_t* qs = (const qid_t*)((uint8_t*)buf + offsetof(struct Rwalk, nwqid));

  *outqids = calloc(rw->nwqid, sizeof(qid_t));
  for (int i = 0; i < rw->nwqid; ++i)
    (*outqids)[i] = swapqid(qs[i]);

  return sizeof(*rw) + sizeof(qid_t) * rw->nwqid;
}

int
encode_Twalk(
  void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t newfid, uint16_t nwnamecount,
  const char* const* names
)
{
  size_t totalSize = sizeof(struct Twalk);
  for (int i = 0; i < nwnamecount; ++i) {
    size_t l = strlen(names[i]);
    if (l > UINT16_MAX)
      return -1;
    totalSize += l + sizeof(uint16_t); /*uint16_t size; char[] data*/
  }

  if (outsize < totalSize) {
    return -1;
  }

  struct Twalk* tw = buf;
  tw->fid = BSWAP32(fid);
  tw->newfid = BSWAP32(newfid);
  tw->nwname = BSWAP16(nwnamecount);
  tw->size = BSWAP32(totalSize);
  tw->tag = BSWAP16(tag);
  tw->type = T9P_TYPE_Twalk;

  /** Start at last offset */
  uint8_t* pb = buf;
  pb += offsetof(struct Twalk, nwname) + sizeof(tw->nwname);

  for (int i = 0; i < nwnamecount; ++i) {
    size_t l = strlen(names[i]);
    wr16(&pb, l);
    wrbuf(&pb, (uint8_t*)names[i], l);
  }

  return totalSize;
}

int
encode_Tread(void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count)
{
  if (bufsize < sizeof(struct Tread))
    return -1;

  struct Tread* tr = buf;
  tr->tag = BSWAP16(tag);
  tr->count = BSWAP32(count);
  tr->offset = BSWAP64(offset);
  tr->fid = BSWAP32(fid);
  tr->size = BSWAP32(sizeof(struct Tread));
  tr->type = T9P_TYPE_Tread;
  return sizeof(*tr);
}

int
decode_Rread(struct Rread* out, const void* buf, size_t buflen)
{
  if (buflen < sizeof(struct Rread))
    return -1;

  const struct Rread* rr = buf;
  out->count = BSWAP32(rr->count);
  out->size = BSWAP32(rr->size);
  out->tag = BSWAP16(rr->tag);
  out->type = rr->type;
  return sizeof(*rr);
}

int
encode_Twrite(
  void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count
)
{
  if (bufsize < sizeof(struct Twrite)) {
    return -1;
  }

  struct Twrite* tw = buf;
  tw->type = T9P_TYPE_Twrite;
  tw->tag = BSWAP16(tag);
  tw->count = BSWAP32(count);
  tw->offset = BSWAP64(offset);
  tw->fid = BSWAP32(fid);
  tw->size = BSWAP32(sizeof(*tw) + count);
  return sizeof(*tw); /** Intentionally excluding count here */
}

int
decode_Rwrite(struct Rwrite* out, const void* buf, size_t len)
{
  if (len < sizeof(*out))
    return -1;

  const struct Rwrite* in = buf;
  out->count = BSWAP32(in->count);
  out->size = BSWAP32(in->size);
  out->type = in->type;
  out->tag = BSWAP16(in->tag);
  return sizeof(*in);
}

int
encode_Tstatfs(void* buf, size_t buflen, uint16_t tag, uint32_t fid)
{
  if (buflen < sizeof(struct Tstatfs))
    return -1;

  struct Tstatfs* st = buf;
  st->fid = BSWAP32(fid);
  st->tag = BSWAP16(tag);
  st->size = BSWAP32(sizeof(*st));
  st->type = T9P_TYPE_Tstatfs;
  return sizeof(*st);
}

int
decode_Rstatfs(struct Rstatfs* st, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*st))
    return -1;

  const struct Rstatfs* in = buf;
  st->type = in->type;
  st->tag = BSWAP16(in->tag);
  st->size = BSWAP32(in->size);
  st->ftype = BSWAP32(in->ftype);
  st->bsize = BSWAP32(in->bsize);
  st->blocks = BSWAP64(in->blocks);
  st->bfree = BSWAP64(in->bfree);
  st->bavail = BSWAP64(in->bavail);
  st->files = BSWAP64(in->files);
  st->ffree = BSWAP64(in->ffree);
  st->fsid = BSWAP64(in->fsid);
  st->namelen = BSWAP32(in->namelen);

  return sizeof(*st);
}

int
encode_Tstat(void* buf, size_t bufsize, uint16_t tag, uint32_t fid)
{
  if (bufsize < sizeof(struct Tstat))
    return -1;

  struct Tstat* ts = buf;
  ts->fid = BSWAP32(fid);
  ts->tag = BSWAP16(tag);
  ts->type = T9P_TYPE_Tstat;
  ts->size = BSWAP32(sizeof(*ts));
  return sizeof(*ts);
}

int
encode_Tgetattr(void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t request_mask)
{
  if (bufsize < sizeof(struct Tgetattr))
    return -1;

  struct Tgetattr* tg = buf;
  tg->fid = BSWAP32(fid);
  tg->tag = BSWAP16(tag);
  tg->type = T9P_TYPE_Tgetattr;
  tg->size = BSWAP32(sizeof(*tg));
  tg->request_mask = BSWAP64(request_mask);
  return sizeof(*tg);
}

int
decode_Rgetattr(struct Rgetattr* attr, const void* buf, size_t bufsize)
{
  if (bufsize < sizeof(*attr))
    return -1;

  const struct Rgetattr* in = buf;

  attr->type = in->type;
  attr->tag = BSWAP16(in->tag);
  attr->size = BSWAP32(in->size);
  attr->valid = BSWAP64(in->valid);
  attr->qid = swapqid(in->qid);
  attr->mode = BSWAP32(in->mode);
  attr->uid = BSWAP32(in->uid);
  attr->gid = BSWAP32(in->gid);
  attr->nlink = BSWAP64(in->nlink);
  attr->rdev = BSWAP64(in->rdev);
  attr->fsize = BSWAP64(in->fsize);
  attr->blksize = BSWAP64(in->blksize);
  attr->blocks = BSWAP64(in->blocks);
  attr->atime_sec = BSWAP64(in->atime_sec);
  attr->atime_nsec = BSWAP64(in->atime_nsec);
  attr->mtime_sec = BSWAP64(in->mtime_sec);
  attr->mtime_nsec = BSWAP64(in->mtime_nsec);
  attr->ctime_sec = BSWAP64(in->ctime_sec);
  attr->ctime_nsec = BSWAP64(in->ctime_nsec);
  attr->btime_sec = BSWAP64(in->btime_sec);
  attr->btime_nsec = BSWAP64(in->btime_nsec);
  attr->gen = BSWAP64(in->gen);
  attr->data_version = BSWAP64(in->data_version);

  return sizeof(*attr);
}

int
encode_Tlcreate(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, const char* name, uint32_t flags,
  uint32_t mode, uint32_t gid
)
{
  const size_t nl = strlen(name);
  const size_t totalSize = sizeof(struct Tlcreate) + nl + sizeof(uint32_t) /*flags*/ +
                           sizeof(uint32_t) /*mode*/ + sizeof(uint32_t) /*gid*/;
  if (buflen < totalSize)
    return -1;

  struct Tlcreate* tl = buf;
  tl->tag = BSWAP16(tag);
  tl->namelen = BSWAP16(nl);
  tl->fid = BSWAP32(fid);
  tl->type = T9P_TYPE_Tlcreate;
  tl->size = BSWAP32(totalSize);

  uint8_t* p = ((uint8_t*)buf) + offsetof(struct Tlcreate, name);
  wrbuf(&p, (uint8_t*)name, nl);
  wr32(&p, flags);
  wr32(&p, mode);
  wr32(&p, gid);

  return totalSize;
}

int
decode_Rlcreate(struct Rlcreate* rl, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rl))
    return -1;

  const struct Rlcreate* in = buf;
  rl->iounit = BSWAP32(in->iounit);
  rl->tag = BSWAP16(in->tag);
  rl->type = in->type;
  rl->qid = swapqid(in->qid);
  rl->size = BSWAP32(in->size);
  return sizeof(*rl);
}

int
encode_Tremove(void* buf, size_t buflen, uint16_t tag, uint32_t fid)
{
  if (buflen < sizeof(struct Tremove))
    return -1;

  struct Tremove* rm = buf;
  rm->type = T9P_TYPE_Tremove;
  rm->fid = BSWAP32(fid);
  rm->size = BSWAP32(sizeof(*rm));
  rm->tag = BSWAP16(tag);
  return sizeof(*rm);
}

int
encode_Tfsync(void* buf, size_t buflen, uint16_t tag, uint32_t fid)
{
  if (buflen < sizeof(struct Tfsync))
    return -1;

  struct Tfsync* tf = buf;
  tf->fid = BSWAP32(fid);
  tf->size = BSWAP32(sizeof(struct Tfsync));
  tf->tag = BSWAP16(tag);
  tf->type = T9P_TYPE_Tfsync;

  return sizeof(struct Tfsync);
}

int
decode_Rfsync(struct Rfsync* rf, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rf))
    return -1;

  const struct Rfsync* in = buf;
  rf->size = BSWAP32(in->size);
  rf->type = in->type;
  rf->tag = BSWAP16(in->tag);
  return sizeof(*rf);
}

int
encode_Tmkdir(
  void* buf, size_t buflen, uint16_t tag, uint32_t dfid, const char* name, uint32_t mode,
  uint32_t gid
)
{
  const size_t nameLen = strlen(name);
  const size_t totalSize =
    sizeof(struct Tmkdir) + sizeof(uint16_t) /*len*/ + nameLen + sizeof(mode) + sizeof(gid);
  if (buflen < totalSize) {
    return -1;
  }

  struct Tmkdir* tm = buf;
  tm->tag = BSWAP16(tag);
  tm->type = T9P_TYPE_Tmkdir;
  tm->dfid = BSWAP32(dfid);
  tm->size = BSWAP32(totalSize);
  uint8_t* b = ((uint8_t*)buf) + offsetof(struct Tmkdir, dfid) + sizeof(uint32_t);
  wr16(&b, nameLen);
  wrbuf(&b, (const uint8_t*)name, nameLen);
  wr32(&b, mode);
  wr32(&b, gid);

  return totalSize;
}

int
decode_Rmkdir(struct Rmkdir* rm, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rm))
    return -1;

  const struct Rmkdir* in = buf;
  *rm = *in;
  rm->qid = swapqid(in->qid);
  rm->size = BSWAP32(in->size);
  rm->tag = BSWAP16(in->tag);
  return sizeof(*in);
}

int
encode_Treadlink(void* buf, size_t buflen, uint16_t tag, uint32_t fid)
{
  if (buflen < sizeof(struct Treadlink))
    return -1;

  struct Treadlink* rl = buf;
  rl->fid = BSWAP32(fid);
  rl->size = BSWAP32(sizeof(*rl));
  rl->tag = BSWAP16(tag);
  rl->type = T9P_TYPE_Treadlink;
  return sizeof *rl;
}

int
decode_Rreadlink(
  struct Rreadlink* rl, char* linkPath, size_t linkPathSize, const void* buf, size_t buflen
)
{
  const size_t minSize = sizeof(struct Rreadlink);
  if (buflen < minSize)
    return -1;

  *rl = *(const struct Rreadlink*)buf;
  rl->tag = BSWAP16(rl->tag);
  rl->size = BSWAP32(rl->size);
  rl->plen = BSWAP16(rl->plen);

  size_t toWrite = (linkPathSize - 1 < rl->plen) ? linkPathSize - 1 : rl->plen;
  memcpy(linkPath, ((const struct Rreadlink*)buf)->path, toWrite);
  linkPath[toWrite] = 0;

  return sizeof(*rl) + rl->plen;
}

int
encode_Tsymlink(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, const char* dst, const char* src,
  uint32_t gid
)
{
  const size_t dstl = strlen(dst);
  const size_t srcl = strlen(src);
  uint32_t packSize = sizeof(struct TRcommon) + sizeof(fid) + sizeof(uint16_t) + dstl +
                      sizeof(uint16_t) + srcl + sizeof(gid);
  if (buflen < packSize)
    return -1;

  struct TRcommon* rc = buf;
  rc->type = T9P_TYPE_Tsymlink;
  rc->size = BSWAP32(packSize);
  rc->tag = BSWAP16(tag);
  uint8_t* b = ((uint8_t*)buf) + sizeof(*rc);
  wr32(&b, fid);
  wrstr(&b, dst, dstl);
  wrstr(&b, src, srcl);
  wr32(&b, gid);

  return packSize;
}

int
decode_Rsymlink(struct Rsymlink* rs, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rs))
    return -1;

  rs->qid = swapqid(rs->qid);
  rs->size = BSWAP32(rs->size);
  rs->tag = BSWAP16(rs->tag);

  return sizeof(*rs);
}

int
decode_TRcommon(struct TRcommon* com, const void* buf, size_t len)
{
  if (len < sizeof(*com))
    return -1;

  *com = *(const struct TRcommon*)buf;
  com->size = BSWAP32(com->size);
  com->tag = BSWAP16(com->tag);
  return sizeof(*com);
}

int
decode_Rlerror(struct Rlerror* rl, const void* buf, size_t len)
{
  if (len < sizeof *rl)
    return -1;

  *rl = *(const struct Rlerror*)buf;
  rl->ecode = BSWAP32(rl->ecode);
  rl->size = BSWAP32(rl->size);
  rl->tag = BSWAP16(rl->tag);
  return sizeof *rl;
}

int
encode_Treaddir(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count
)
{
  if (buflen < sizeof(struct Treaddir))
    return -1;

  struct Treaddir* tr = buf;
  tr->count = BSWAP32(count);
  tr->type = T9P_TYPE_Treaddir;
  tr->fid = BSWAP32(fid);
  tr->offset = BSWAP64(offset);
  tr->size = BSWAP32(sizeof(*tr));
  tr->tag = BSWAP16(tag);
  return sizeof *tr;
}

int
decode_Rreaddir(
  struct Rreaddir* rd, const void* buf, size_t buflen,
  void (*parse_dir_callback)(void*, struct Rreaddir_dir, const char*), void* param
)
{
  const uint8_t* bp = buf;
  struct Rreaddir_dir hdr;
  uint32_t off = 0;

  if (buflen < sizeof(*rd))
    return -1;

  *rd = *(const struct Rreaddir*)buf;
  rd->count = BSWAP32(rd->count);
  rd->size = BSWAP32(rd->size);
  rd->tag = BSWAP16(rd->tag);

  while (off < rd->count) {
    if (off + sizeof(hdr) >= rd->count)
      return -1;
  
    /** off is relative to start of data (after hdr *rd) */
    hdr = *(const struct Rreaddir_dir*)(bp + off + sizeof(*rd));
  
    hdr.namelen = BSWAP16(hdr.namelen);
    hdr.offset = BSWAP64(hdr.offset);
    hdr.qid = swapqid(hdr.qid);

    off += sizeof(hdr);
    if (off + hdr.namelen > rd->count)
      return -1;

    parse_dir_callback(param, hdr, (const char*)(bp + off + sizeof(*rd)));
    off += hdr.namelen;
  }
  return 0;
}

/**
 * size[4] Tunlinkat tag[2] dirfd[4] name[s] flags[4]
 * size[4] Runlinkat tag[2]
 */
int
encode_Tunlinkat(
  void* buf, size_t buflen, uint16_t tag, uint32_t dfid, const char* name, uint32_t flags
)
{
  const uint16_t nlen = strlen(name);
  const uint32_t totalSize = sizeof(struct Tunlinkat) + nlen + sizeof(flags) + sizeof(nlen);
  if (buflen < totalSize)
    return -1;

  struct Tunlinkat* tu = buf;
  tu->dirfd = BSWAP32(dfid);
  tu->tag = BSWAP16(tag);
  tu->type = T9P_TYPE_Tunlinkat;
  tu->size = BSWAP32(totalSize);

  uint8_t* off = sizeof(*tu) + (uint8_t*)buf;
  wrstr(&off, name, nlen);
  wr32(&off, flags);

  return totalSize;
}

int
decode_Runlinkat(struct Runlinkat* ru, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*ru))
    return -1;

  const struct Runlinkat* cu = buf;
  *ru = *cu;
  ru->size = BSWAP32(cu->size);
  ru->tag = BSWAP16(cu->tag);
  return sizeof(*cu);
}

/**
 * size[4] Trenameat tag[2] olddirfid[4] oldname[s] newdirfid[4] newname[s]
 * size[4] Rrenameat tag[2]
 */
int
encode_Trenameat(
  void* buf, size_t buflen, uint16_t tag, uint32_t olddirfd, const char* oldname, uint32_t newdirfd,
  const char* newname
)
{
  const uint16_t oldnamelen = strlen(oldname);
  const uint16_t newnamelen = strlen(newname);
  const uint32_t totalSize = sizeof(struct TRcommon) + sizeof(olddirfd) + sizeof(oldnamelen) +
                             sizeof(newnamelen) + oldnamelen + newnamelen + sizeof(newdirfd);

  if (buflen < totalSize) {
    return -1;
  }

  struct TRcommon* com = buf;
  com->tag = BSWAP16(tag);
  com->type = T9P_TYPE_Trenameat;
  com->size = BSWAP32(totalSize);

  uint8_t* ptr = sizeof(*com) + (uint8_t*)buf;
  wr32(&ptr, olddirfd);
  wrstr(&ptr, oldname, oldnamelen);
  wr32(&ptr, newdirfd);
  wrstr(&ptr, newname, newnamelen);

  return totalSize;
}

int
decode_Rrenameat(struct Rrenameat* ra, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*ra))
    return -1;

  const struct Rrenameat* ia = buf;
  *ra = *ia;
  ra->size = BSWAP32(ra->size);
  ra->tag = BSWAP16(ra->tag);
  return sizeof(*ra);
}

int
encode_Tsetattr(
  void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint32_t valid,
  const struct t9p_setattr* attr
)
{
  if (buflen < sizeof(struct Tsetattr))
    return -1;
  struct Tsetattr* ts = buf;
  ts->type = T9P_TYPE_Tsetattr;
  ts->tag = BSWAP16(tag);
  ts->size = BSWAP32(sizeof(struct Tsetattr));

  ts->fid = BSWAP32(fid);
  ts->valid = BSWAP32(valid);
  ts->mode = BSWAP32(attr->mode);
  ts->uid = BSWAP32(attr->uid);
  ts->gid = BSWAP32(attr->gid);
  ts->fsize = BSWAP64(attr->size);
  ts->atime_sec = BSWAP64(attr->atime_sec);
  ts->atime_nsec = BSWAP64(attr->atime_nsec);
  ts->mtime_sec = BSWAP64(attr->mtime_sec);
  ts->mtime_nsec = BSWAP64(attr->mtime_nsec);

  return sizeof *ts;
}

int
decode_Rsetattr(struct Rsetattr* rs, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rs))
    return -1;

  *rs = *(const struct Rsetattr*)buf;
  rs->size = BSWAP32(rs->size);
  rs->tag = BSWAP16(rs->tag);
  return sizeof(*rs);
}

int
encode_Tlink(void* buf, size_t buflen, uint16_t tag, uint32_t dfid, uint32_t fid, const char* name)
{
  const size_t nl = strlen(name);
  const size_t totalSize = sizeof(struct Tlink) + nl;
  if (buflen < totalSize)
    return -1;
  
  struct Tlink* tl = buf;
  tl->dfid = BSWAP32(dfid);
  tl->fid = BSWAP32(fid);
  tl->size = BSWAP32(totalSize);
  tl->tag = BSWAP16(tag);
  tl->type = T9P_TYPE_Tlink;
  uint8_t* pos = buf;
  pos += offsetof(struct Tlink, namelen);
  wrstr(&pos, name, nl);

  return totalSize;
}

int
decode_Rlink(struct Rlink* rl, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rl))
    return -1;
  
  const struct Rlink* rrl = buf;
  rl->size = BSWAP32(rrl->size);
  rl->tag = BSWAP16(rrl->tag);
  rl->type = rrl->type;
  return sizeof(*rl);
}

int
encode_Trename(void* buf, size_t buflen, uint16_t tag, uint32_t fid, uint32_t dfid,
  const char* name)
{
  const size_t nl = strlen(name);
  const size_t totalSize = sizeof(struct Trename) + nl;
  if (buflen < totalSize)
    return -1;
  
  struct Trename* tr = buf;
  tr->dfid = BSWAP32(dfid);
  tr->fid = BSWAP32(fid);
  tr->size = BSWAP32(totalSize);
  tr->type = T9P_TYPE_Trename;
  tr->tag = BSWAP16(tag);
  uint8_t* pos = buf;
  pos += offsetof(struct Trename, namelen);
  wrstr(&pos, name, nl);
  
  return totalSize;
}

int
decode_Rrename(struct Rrename* rn, const void* buf, size_t buflen)
{
  if (buflen < sizeof(*rn))
    return -1;

  *rn = *(struct Rrename*)buf;
  rn->size = BSWAP32(rn->size);
  rn->tag = BSWAP16(rn->tag);
  return sizeof(*rn);
}


int encode_Tmknod(void* buf, size_t buflen, uint16_t tag, uint32_t dfid, const char* name,
  uint32_t mode, uint32_t major, uint32_t minor, uint32_t gid)
{
  const size_t nl = strlen(name);
  const size_t totalSize = sizeof(struct TRcommon) + sizeof(uint32_t) + sizeof(uint16_t)
    + nl + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
  if (buflen < totalSize)
    return -1;

  uint8_t* p = buf;
  wr32(&p, totalSize);
  wr8(&p, T9P_TYPE_Tmknod);
  wr16(&p, tag);
  wr32(&p, dfid);
  wrstr(&p, name, nl);
  wr32(&p, mode);
  wr32(&p, major);
  wr32(&p, minor);
  wr32(&p, gid);

  return totalSize;
}

int decode_Rmknod(struct Rmknod* rm, const void* buf, size_t buflen)
{
  if (buflen < sizeof *rm)
    return -1;

  *rm = *(struct Rmknod*)buf;
  rm->qid = swapqid(rm->qid);
  rm->size = BSWAP32(rm->size);
  rm->tag = BSWAP16(rm->tag);

  return sizeof *rm;
}