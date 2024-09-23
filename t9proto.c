
#include "t9proto.h"
#include <byteswap.h>
#include <string.h>
#include <stdlib.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#define BSWAP32(x) bswap_32(x)
#define BSWAP16(x) bswap_16(x)
#define BSWAP64(x) bswap_64(x)
#else
#define BSWAP32(x) (x)
#define BSWAP16(x) (x)
#define BSWAP64(x) (x)
#endif

#define ISWAP16(x) (x) = BSWAP16(x)
#define ISWAP32(x) (x) = BSWAP32(x)
#define ISWAP64(x) (x) = BSWAP64(x)

qid_t swapqid(qid_t in) {
    qid_t q = {
        .path = BSWAP64(in.path),
        .type = in.type,
        .version = BSWAP32(in.version)
    };
    return q;
}

void wr64(uint8_t** pos, uint64_t val) {
    *(uint64_t*)(*pos) = BSWAP64(val);
    *pos += 8;
}

void wr32(uint8_t** pos, uint32_t val) {
    *(uint32_t*)(*pos) = BSWAP32(val);
    *pos += 4;
}

void wr16(uint8_t** pos, uint16_t val) {
    *(uint16_t*)(*pos) = BSWAP16(val);
    *pos += 2;
}

void wrbuf(uint8_t** pos, const uint8_t* buf, uint32_t bl) {
    for (uint32_t n = 0; n < bl; ++n)
        *(*pos)++ = buf[n];
}

const char* t9p_type_string(int type) {
    switch(type) {
    case T9P_TYPE_Rlerror:  return "Rlerror";
    case T9P_TYPE_Tlopen:   return "Tlopen";
    case T9P_TYPE_Rlopen:   return "Rlopen";
    case T9P_TYPE_Tlcreate: return "Tlcreate";
    case T9P_TYPE_Rlcreate: return "Rlcreate";
    case T9P_TYPE_Tgetattr: return "Tgetattr";
    case T9P_TYPE_Rgetattr: return "Rgetattr";
    case T9P_TYPE_Tversion: return "Tversion";
    case T9P_TYPE_Rversion: return "Rversion";
    case T9P_TYPE_Tauth:    return "Tauth";
    case T9P_TYPE_Rauth:    return "Rauth";
    case T9P_TYPE_Tattach:  return "Tattach";
    case T9P_TYPE_Rattach:  return "Rattach";
    case T9P_TYPE_Terror:   return "Terror";
    case T9P_TYPE_Rerror:   return "Rerror";
    case T9P_TYPE_Tflush:   return "Tflush";
    case T9P_TYPE_Rflush:   return "Rflush";
    case T9P_TYPE_Twalk:    return "Twalk";
    case T9P_TYPE_Rwalk:    return "Rwalk";
    case T9P_TYPE_Topen:    return "Topen";
    case T9P_TYPE_Ropen:    return "Ropen";
    case T9P_TYPE_Tcreate:  return "Tcreate";
    case T9P_TYPE_Rcreate:  return "Rcreate";
    case T9P_TYPE_Tread:    return "Tread";
    case T9P_TYPE_Rread:    return "Rread";
    case T9P_TYPE_Twrite:   return "Twrite";
    case T9P_TYPE_Rwrite:   return "Rwrite";
    case T9P_TYPE_Tclunk:   return "Tclunk";
    case T9P_TYPE_Rclunk:   return "Rclunk";
    case T9P_TYPE_Tremove:  return "Tremove";
    case T9P_TYPE_Rremove:  return "Rremove";
    case T9P_TYPE_Tstat:    return "Tstat";
    case T9P_TYPE_Rstat:    return "Rstat";
    case T9P_TYPE_Twstat:   return "Twstat";
    case T9P_TYPE_Rwstat:   return "Rwstat";
    default: return "Tunknown";
    }
}

int encode_Tversion(void* pout, size_t outsize, uint16_t tag, uint32_t msize, uint16_t version_len, const uint8_t* version) {
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

int decode_Rversion(struct Rversion** out, const void* buf, size_t buflen) {
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

int encode_Tattach(void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t afid, uint16_t uname_len, const uint8_t* uname, uint16_t aname_len, const uint8_t* aname, uint32_t uid) {
    const int totalsz = sizeof(struct Tattach) + uname_len + sizeof(uint16_t) /*aname_len*/ + aname_len + sizeof(uint32_t) /*uid*/;
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

int decode_Rattach(struct Rattach* out, const void* buf, size_t buflen) {
    if (buflen < sizeof(*out))
        return -1;

    *out = *(struct Rattach*)buf;
    ISWAP32(out->size);
    ISWAP16(out->tag);
    ISWAP32(out->qid.version);
    ISWAP64(out->qid.path);
    return sizeof(*out);
}

int encode_Tclunk(void* buf, size_t outsize, uint16_t tag, uint32_t fid) {
    if (outsize < sizeof(struct Tclunk))
        return -1;

    struct Tclunk* tc = buf;
    tc->size = BSWAP32(sizeof(*tc));
    tc->fid = BSWAP32(fid);
    tc->type = T9P_TYPE_Tclunk;
    tc->tag = BSWAP16(tag);

    return sizeof(*tc);
}

int encode_Tlopen(void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t flags) {
    if (outsize < sizeof(struct Tlopen))
        return -1;

    struct Tlopen* tl = buf;
    tl->fid = BSWAP32(fid);
    tl->flags = BSWAP32(flags);
    tl->size = BSWAP64(sizeof(*tl));
    tl->tag = BSWAP16(tag);
    tl->type = T9P_TYPE_Tlopen;

    return sizeof(*tl);
}

int decode_Rlopen(struct Rlopen* out, const void* buf, size_t buflen) {
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

int decode_Rwalk(struct Rwalk* rw, const void* buf, size_t buflen, qid_t** outqids) {
    if (buflen < sizeof(struct Rwalk))
        return -1;

    *rw = *(struct Rwalk*)buf;
    ISWAP32(rw->size);
    ISWAP16(rw->tag);
    ISWAP16(rw->nwqid);
    const qid_t* qs = (const qid_t*)((uint8_t*)buf + offsetof(struct Rwalk, nwqid));

    *outqids = malloc(sizeof(qid_t) * rw->nwqid);
    for (int i = 0; i < rw->nwqid; ++i)
        (*outqids)[i] = swapqid(qs[i]);

    return sizeof(*rw) + sizeof(qid_t) * rw->nwqid;
}

int encode_Twalk(void* buf, size_t outsize, uint16_t tag, uint32_t fid, uint32_t newfid, uint16_t nwnamecount, const char* const* names) {
    size_t totalSize = sizeof(struct Twalk);
    for (int i = 0; i < nwnamecount; ++i) {
        size_t l = strlen(names[i]);
        if (l > UINT16_MAX) return -1;
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

int encode_Tread(void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count) {
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

int decode_Rread(struct Rread* out, const void* buf, size_t buflen) {
    if (buflen < sizeof(struct Rread))
        return -1;

    const struct Rread* rr = buf;
    out->count = BSWAP32(rr->count);
    out->size = BSWAP32(rr->size);
    out->tag = BSWAP16(rr->tag);
    out->type = rr->type;
    return sizeof(*rr);
}

int encode_Twrite(void* buf, size_t bufsize, uint16_t tag, uint32_t fid, uint64_t offset, uint32_t count) {
    if (bufsize < sizeof(struct Twrite)) {
        return -1;
    }

    struct Twrite* tw = buf;
    tw->type = T9P_TYPE_Twrite;
    tw->tag = BSWAP16(tag);
    tw->count = BSWAP32(count);
    tw->offset = BSWAP64(offset);
    tw->fid = BSWAP32(fid);
    tw->size = sizeof(*tw) + count;
    return sizeof(*tw); /** Intentionally excluding count here */
}

int decode_Rwrite(struct Rwrite* out, const void* buf, size_t len) {
    if (len < sizeof(*out))
        return -1;

    const struct Rwrite* in = buf;
    out->count = BSWAP32(in->count);
    out->size = BSWAP32(in->size);
    out->type = in->type;
    out->tag = BSWAP16(in->tag);
    return sizeof(*in);
}