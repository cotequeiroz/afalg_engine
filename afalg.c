/*
 *  OpenSSL AFALG engine
 *
 *  Copyright 2019 Eneas Ulir de Queiroz
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * Based on The OpenSSL Project Authors' devcrypto engine.
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 */

#ifdef AFALG_ZERO_COPY
/* Required for vmsplice */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# include <sys/uio.h>

static size_t zc_maxsize, pagemask;
#endif

#include <asm/byteorder.h>
#include <asm/types.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef AFALG_NO_CRYPTOUSER
# include <linux/cryptouser.h>
#elif !defined(CRYPTO_MAX_NAME)
# define CRYPTO_MAX_NAME 64
#endif
#include <linux/if_alg.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

/* linux/crypto.h is not public, so we must define the type and masks here,
 * and hope they are still valid. */
#ifndef CRYPTO_ALG_TYPE_MASK
# define CRYPTO_ALG_TYPE_MASK            0x0000000f
# define CRYPTO_ALG_TYPE_BLKCIPHER       0x00000004
# define CRYPTO_ALG_TYPE_SKCIPHER        0x00000005
# define CRYPTO_ALG_TYPE_SHASH           0x0000000e
# define CRYPTO_ALG_TYPE_AHASH           0x0000000f
# define CRYPTO_ALG_KERN_DRIVER_ONLY     0x00001000
# define CRYPTO_ALG_INTERNAL             0x00002000
#endif

#ifndef OSSL_NELEM
# define OSSL_NELEM(x)                (sizeof(x)/sizeof((x)[0]))
#endif
#define engine_afalg_id "afalg"

#define AFALG_REQUIRE_ACCELERATED 0 /* require confirmation of acceleration */
#define AFALG_USE_SOFTWARE        1 /* allow software drivers */
#define AFALG_REJECT_SOFTWARE     2 /* only disallow confirmed software drivers */

#ifndef AFALG_DEFAULT_USE_SOFTDRIVERS
# define AFALG_DEFAULT_USE_SOFTDRIVERS AFALG_REJECT_SOFTWARE
#endif
static int use_softdrivers = AFALG_DEFAULT_USE_SOFTDRIVERS;

/*
 * cipher/digest status & acceleration definitions
 * Make sure the defaults are set to 0
 */

struct driver_info_st {
    enum afalg_status_t {
        AFALG_STATUS_FAILURE       = -3, /* unusable for other reason */
        AFALG_STATUS_NO_COPY       = -2, /* hash state copy not supported */
        AFALG_STATUS_NO_OPEN       = -1, /* bind call failed */
        AFALG_STATUS_UNKNOWN       =  0, /* not tested yet */
        AFALG_STATUS_USABLE        =  1  /* algo can be used */
    } status;

    enum afalg_accelerated_t {
        AFALG_NOT_ACCELERATED      = -1, /* software implemented */
        AFALG_ACCELERATION_UNKNOWN =  0, /* acceleration support unkown */
        AFALG_ACCELERATED          =  1  /* hardware accelerated */
    } accelerated;
};

static int get_afalg_socket(const char *salg_name, const char *salg_type,
                            const __u32 feat, const __u32 mask)
{
    int fd = -1;
    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *)sa.salg_type, salg_type, sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *)sa.salg_name, salg_name, sizeof(sa.salg_name));
    sa.salg_feat = feat;
    sa.salg_mask = mask;
    if ((fd = socket(AF_ALG, SOCK_SEQPACKET, 0)) < 0) {
        SYSerr(SYS_F_SOCKET, errno);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
        return fd;

    close(fd);
    return -1;
}

static int afalg_closefd(int fd)
{
    int ret;

    if (fd < 0 || (ret = close(fd)) == 0)
        return 0;
/* For compatibility with openssl 1.1.0 */
#ifdef SYS_F_CLOSE
    SYSerr(SYS_F_CLOSE, errno);
#endif
    return ret;
}

struct afalg_alg_info {
    char alg_name[CRYPTO_MAX_NAME];
    char driver_name[CRYPTO_MAX_NAME];
    __u32 priority;
    __u32 flags;
};

static struct afalg_alg_info *afalg_alg_list = NULL;
static int afalg_alg_list_count = -1; /* no info available */

#ifndef AFALG_NO_CRYPTOUSER
static int prepare_afalg_alg_list(void)
{
    int ret = -EFAULT;

    /* NETLINK_CRYPTO specific */
    void *buf = NULL;
    struct nlmsghdr *res_n;
    size_t buf_size;
    struct {
        struct nlmsghdr n;
        struct crypto_user_alg cru;
    } req;
    struct crypto_user_alg *cru_res = NULL;
    struct afalg_alg_info *list;

    /* AF_NETLINK specific */
    struct sockaddr_nl nl;
    struct iovec iov;
    struct msghdr msg;
    struct rtattr *rta;
    int nlfd, msg_len, rta_len, list_count;
    __u32 alg_type;

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));
    list = afalg_alg_list = NULL;
    afalg_alg_list_count = -1;

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.cru));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    req.n.nlmsg_type = CRYPTO_MSG_GETALG;

    /* open netlink socket */
    nlfd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
    if (nlfd < 0) {
        if (errno != EPROTONOSUPPORT) /* crypto_user module not available */
            perror("Netlink error: cannot open netlink socket");
        return -errno;
    }
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    if (bind(nlfd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
        perror("Netlink error: cannot bind netlink socket");
        ret = -errno;
        goto out;
    }

    /* sending data */
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    iov.iov_base = (void*) &req.n;
    iov.iov_len = req.n.nlmsg_len;
    msg.msg_name = &nl;
    msg.msg_namelen = sizeof(nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(nlfd, &msg, 0) < 0) {
        perror("Netlink error: sendmsg failed");
        ret = -errno;
        goto out;
    }

    /* get the msg size */
    iov.iov_base = NULL;
    iov.iov_len = 0;
    buf_size = recvmsg(nlfd, &msg, MSG_PEEK | MSG_TRUNC);

    buf = OPENSSL_zalloc(buf_size);
    iov.iov_base = buf;
    iov.iov_len = buf_size;

    while (1) {
        if ((msg_len = recvmsg(nlfd, &msg, 0)) <= 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            if (msg_len == 0)
                perror("Nelink error: no data");
            else
                perror("Nelink error: netlink receive error");
            ret = -errno;
            goto out;
        }
        if ((u_int32_t)msg_len > buf_size) {
            perror("Netlink error: received too much data");
            ret = -errno;
            goto out;
        }
        break;
    }

    ret = -EFAULT;
    list_count = 0;
    for (res_n = (struct nlmsghdr *)buf; (ret = NLMSG_OK(res_n, msg_len));
         res_n = NLMSG_NEXT(res_n, msg_len)) {
        if (res_n->nlmsg_type == NLMSG_ERROR) {
            ret = 0;
            goto out;
        }
        cru_res = NLMSG_DATA(res_n);
        if (res_n->nlmsg_type != CRYPTO_MSG_GETALG
            || !cru_res || res_n->nlmsg_len < NLMSG_SPACE(sizeof(*cru_res)))
            continue;
        alg_type = cru_res->cru_flags & CRYPTO_ALG_TYPE_MASK;
        if ((alg_type != CRYPTO_ALG_TYPE_SKCIPHER && alg_type != CRYPTO_ALG_TYPE_BLKCIPHER
             && alg_type != CRYPTO_ALG_TYPE_SHASH && alg_type != CRYPTO_ALG_TYPE_AHASH)
            || cru_res->cru_flags & CRYPTO_ALG_INTERNAL)
            continue;
        list = OPENSSL_realloc(afalg_alg_list, (list_count + 1) * sizeof(struct afalg_alg_info));
        if (list == NULL) {
            OPENSSL_free(afalg_alg_list);
            afalg_alg_list = NULL;
            ret = -ENOMEM;
            goto out;
        }
        memset(&list[list_count], 0, sizeof(struct afalg_alg_info));
        afalg_alg_list = list;

        rta_len=msg_len;
        list[list_count].priority = 0;
        for (rta = (struct rtattr *)(((char *) cru_res)
                                     + NLMSG_ALIGN(sizeof(struct crypto_user_alg)));
             (ret = RTA_OK (rta, rta_len)); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == CRYPTOCFGA_PRIORITY_VAL) {
                list[list_count].priority = *((__u32 *)RTA_DATA(rta));
                break;
            }
        }

        OPENSSL_strlcpy(list[list_count].alg_name, cru_res->cru_name,
                        sizeof(list->alg_name));
        OPENSSL_strlcpy(list[list_count].driver_name, cru_res->cru_driver_name,
                        sizeof(list->driver_name));
        list[list_count].flags = cru_res->cru_flags;
        list_count++;
    }
    ret = afalg_alg_list_count = list_count;
out:
    close(nlfd);
    OPENSSL_free(buf);
    return ret;
}
#endif

#ifndef AFALG_NO_CRYPTOUSER
static const char *
afalg_get_driver_name(const char *alg_name,
                      enum afalg_accelerated_t expected_accel)
{
    int i;
    __u32 priority = 0;
    int found = 0;
    enum afalg_accelerated_t accel;
    const char *driver_name = "unknown";

    for (i = 0; i < afalg_alg_list_count; i++) {
        if (strcmp(afalg_alg_list[i].alg_name, alg_name) ||
            priority > afalg_alg_list[i].priority)
            continue;
        if (afalg_alg_list[i].flags & CRYPTO_ALG_KERN_DRIVER_ONLY)
            accel = AFALG_ACCELERATED;
        else
            accel = AFALG_NOT_ACCELERATED;
        if ((found && priority == afalg_alg_list[i].priority)
            || accel != expected_accel) {
            driver_name = "**unreliable info**";
        } else {
            found = 1;
            priority = afalg_alg_list[i].priority;
            driver_name = afalg_alg_list[i].driver_name;
        }
    }
    return driver_name;
}
#endif

/******************************************************************************
 *
 * Ciphers
 *
 *****/

struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    const char *name;
#ifndef AFALG_NO_FALLBACK
    const EVP_CIPHER *((*fallback) (void));
    int fb_threshold;
#endif
};

struct cipher_ctx {
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
#ifndef AFALG_NO_FALLBACK
    EVP_CIPHER_CTX *fallback;
    int fb_threshold;
#endif
    int control_is_set;
    const struct cipher_data_st *cipher_d;
    unsigned int blocksize, num;
    unsigned char partial[EVP_MAX_BLOCK_LENGTH];
};

static const struct cipher_data_st cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, "cbc(des)",
#ifndef AFALG_NO_FALLBACK
      EVP_des_cbc, 320
#endif
    },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, "cbc(des3_ede)",
#ifndef AFALG_NO_FALLBACK
      EVP_des_ede3_cbc, 96
#endif
    },
#endif
#ifndef OPENSSL_NO_BF
    { NID_bf_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(blowfish)" },
#endif
#ifndef OPENSSL_NO_CAST
    { NID_cast5_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(cast5)" },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_cbc, 1536
#endif
    },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_cbc, 1152
#endif
    },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_cbc, 960
#endif
    },
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_ctr, 1360
#endif
    },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_ctr, 1152
#endif
    },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_ctr, 960
#endif
    },
    { NID_aes_128_ecb, 16, 128 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_ecb, 2048
#endif
    },
    { NID_aes_192_ecb, 16, 192 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_ecb, 1440
#endif
    },
    { NID_aes_256_ecb, 16, 256 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_ecb, 1152
#endif
    },
#if 0
/* Current camellia kernel module does not implement the skcipher
 * interface, necessary to work with AF_ALG */
#ifndef OPENSSL_NO_CAMELLIA
    { NID_camellia_128_cbc, 16, 128 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
    { NID_camellia_192_cbc, 16, 192 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
    { NID_camellia_256_cbc, 16, 256 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
#endif
#endif
};

static size_t find_cipher_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        if (nid == cipher_data[i].nid)
            return i;
    return (size_t)-1;
}

static size_t get_cipher_data_index(int nid)
{
    size_t i = find_cipher_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static int afalg_set_key(int sfd, const void *key, int keylen)
{
    if (setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, keylen) >= 0)
        return 1;
    SYSerr(SYS_F_SETSOCKOPT, errno);
    return 0;
}

static int afalg_set_control(struct msghdr *msg, int op,
                             const unsigned char *iv, unsigned int ivlen)
{
    size_t set_op_len = sizeof(op);
    size_t set_iv_len;
    struct cmsghdr *cmsg;
    struct af_alg_iv *aiv;

    if (!iv)
        ivlen = 0;
    set_iv_len = offsetof(struct af_alg_iv, iv) + ivlen;
    msg->msg_controllen = CMSG_SPACE(set_op_len)
                        + (ivlen > 0 ? CMSG_SPACE(set_iv_len) : 0);
    msg->msg_control = OPENSSL_zalloc(msg->msg_controllen);
    if (msg->msg_control == NULL) {
        perror("afalg_set_control: OPENSSL_zalloc");
        return 0;
    }
    cmsg = CMSG_FIRSTHDR(msg);
    if (cmsg == NULL) {
        fprintf(stderr, "%s: CMSG_FIRSTHDR error setting op.\n", __func__);
        goto err;
    }
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(op));
    *(CMSG_DATA(cmsg)) = op;
    if (ivlen == 0)
        return 1;

    cmsg = CMSG_NXTHDR(msg, cmsg);
    if (cmsg == NULL) {
        fprintf(stderr, "%s: CMSG_NXTHDR error setting iv.\n", __func__);
        goto err;
    }
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
    aiv = (void *)CMSG_DATA(cmsg);
    aiv->ivlen = ivlen;
    memcpy(aiv->iv, iv, ivlen);
    return 1;

err:
    free(msg->msg_control);
    msg->msg_control = NULL;
    msg->msg_controllen = 0;
    return 0;
}

#ifndef AFALG_NO_FALLBACK
static EVP_CIPHER_CTX *cipher_fb_ctx[OSSL_NELEM(cipher_data)][2] = { { NULL, }, };
static int cipher_fb_threshold[OSSL_NELEM(cipher_data)] = { 0, };

static int prepare_cipher_fallback(int i, int enc)
{
    cipher_fb_ctx[i][enc] = EVP_CIPHER_CTX_new();

    if (!cipher_fb_ctx[i][enc])
        return 0;

    if (EVP_CipherInit_ex(cipher_fb_ctx[i][enc], cipher_data[i].fallback(),
                          NULL, NULL, NULL, enc))
        return 1;
    EVP_CIPHER_CTX_free(cipher_fb_ctx[i][enc]);
    cipher_fb_ctx[i][enc] = NULL;
    return 0;
}

static int cipher_fb_init(struct cipher_ctx *cipher_ctx,
                          EVP_CIPHER_CTX *source_ctx,
                          const unsigned char *key,
                          const unsigned char *iv, int enc)
{
    cipher_ctx->fallback = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *fb_cipher;
    int (*fb_init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc);

    if (!EVP_CIPHER_CTX_copy(cipher_ctx->fallback, source_ctx))
        goto out;
    if (!(fb_cipher = EVP_CIPHER_CTX_cipher(cipher_ctx->fallback)))
        goto out;
    if (!(fb_init = EVP_CIPHER_meth_get_init(fb_cipher)))
        goto out;
    if (fb_init(cipher_ctx->fallback, key, iv, enc))
        return 1;
out:
    free(cipher_ctx->fallback);
    cipher_ctx->fallback = NULL;
    return 0;
}
#endif

static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t i = get_cipher_data_index(EVP_CIPHER_CTX_nid(ctx));
    const struct cipher_data_st *cipher_d = &cipher_data[i];
    int keylen;
    int mode = EVP_CIPHER_CTX_mode(ctx);
    __u32 afalg_mask;

    if (cipher_ctx->bfd == -1) {
        if (mode == EVP_CIPH_CTR_MODE)
            cipher_ctx->blocksize = cipher_d->blocksize;
        if (use_softdrivers == AFALG_REQUIRE_ACCELERATED)
            afalg_mask = CRYPTO_ALG_KERN_DRIVER_ONLY;
        else
            afalg_mask = 0;
        cipher_ctx->bfd = get_afalg_socket(cipher_d->name, "skcipher",
                                           afalg_mask, afalg_mask);
        if (cipher_ctx->bfd < 0) {
            SYSerr(SYS_F_BIND, errno);
            return 0;
        }
    }
    if (cipher_ctx->sfd != -1) {
        close(cipher_ctx->sfd);
        cipher_ctx->sfd = -1;
    }
    if (key != NULL) {
        if ((keylen = EVP_CIPHER_CTX_key_length(ctx)) > 0
            && !afalg_set_key(cipher_ctx->bfd, key, keylen)) {
            fprintf(stderr, "cipher_init: Error setting key.\n");
            goto err;
        }
#ifndef AFALG_NO_FALLBACK
        if (cipher_fb_ctx[i][enc]) {
            if (!cipher_fb_init(cipher_ctx, cipher_fb_ctx[i][enc], key, iv,
                                enc)) {
                fprintf(stderr, "cipher_init: Warning: Cannot set fallback key."
                                " Fallback will not be used!\n");
            } else {
                cipher_ctx->fb_threshold = cipher_fb_threshold[i];
            }
        }
#endif
    }
    if ((cipher_ctx->sfd = accept(cipher_ctx->bfd, NULL, 0)) < 0) {
        perror("cipher_init: accept");
        goto err;
    }
#ifdef AFALG_ZERO_COPY
    if (pipe(cipher_ctx->pipes) < 0) {
        perror("cipher_init: pipes");
        goto err;
    }
#endif
    cipher_ctx->cipher_d = cipher_d;
    return 1;

err:
    close(cipher_ctx->bfd);
    if (cipher_ctx->sfd >= 0) {
        close(cipher_ctx->sfd);
        cipher_ctx->sfd = -1;
    }
    return 0;
}

static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct msghdr msg = { 0 };
    struct iovec iov;
    ssize_t res = -1;
    int ret = 0;
    int op = EVP_CIPHER_CTX_encrypting(ctx) ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    int ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);

#ifndef AFALG_NO_FALLBACK
    if (inl < cipher_ctx->fb_threshold) {
        const EVP_CIPHER *fb_cipher;
        int (*fb_do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t inl);
        if ((fb_cipher = EVP_CIPHER_CTX_cipher(cipher_ctx->fallback))
            && (fb_do_cipher = EVP_CIPHER_meth_get_do_cipher(fb_cipher))) {
            if (ivlen) {
                memcpy(EVP_CIPHER_CTX_iv_noconst(cipher_ctx->fallback), iv, ivlen);
                cipher_ctx->control_is_set = 0;
            }
            return fb_do_cipher (cipher_ctx->fallback, out, in, inl);
        }
    }
#endif
    if (!cipher_ctx->control_is_set) {
        afalg_set_control(&msg, op, iv, ivlen);
        cipher_ctx->control_is_set = 1;
    }
    iov.iov_base = (void *)in;
    iov.iov_len = inl;
#ifdef AFALG_ZERO_COPY
    if (inl <= zc_maxsize && ((size_t)in & pagemask) == 0) {
        if (msg.msg_control && sendmsg(cipher_ctx->sfd, &msg, 0) < 0) {
            perror ("afalg_do_cipher: sendmsg");
            goto out;
        }
        res = vmsplice(cipher_ctx->pipes[1], &iov, 1,
                       SPLICE_F_GIFT & SPLICE_F_MORE);
        if (res < 0) {
            perror("afalg_do_cipher: vmsplice");
            goto out;
        } else if (res != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: vmsplice: sent %zd bytes != len %zd\n",
                    res, inl);
            goto out;
        }
        res = splice(cipher_ctx->pipes[0], NULL, cipher_ctx->sfd, NULL, inl, 0);
        if (res < 0) {
            perror("afalg_do_cipher: splice");
            goto out;
        } else if (res != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: splice: spliced %zd bytes != len %zd\n",
                    res, inl);
            goto out;
        }
    } else
#endif
    {
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        if ((res = sendmsg(cipher_ctx->sfd, &msg, 0)) < 0) {
            perror("afalg_do_cipher: sendmsg");
            goto out;
        } else if (res != (ssize_t) inl) {
            fprintf(stderr, "afalg_do_cipher: sent %zd bytes != len %zd\n",
                    res, inl);
            goto out;
        }
    }
    if ((res = read(cipher_ctx->sfd, out, inl)) == (ssize_t) inl)
        ret = 1;
    else
        fprintf(stderr, "afalg_do_cipher: read %zd bytes != len %zd\n",
                res, inl);
out:
    if (msg.msg_control)
        OPENSSL_free(msg.msg_control);
    return ret;
}

static int cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
#ifndef AFALG_NO_FALLBACK
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    size_t ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned char saved_iv[EVP_MAX_IV_LENGTH];
    int ret;

    assert(inl >= ivlen);
    if (!enc)
        memcpy(saved_iv, in + inl - ivlen, ivlen);
    if ((ret = afalg_do_cipher(ctx, out, in, inl)))
        memcpy(iv, enc ? out + inl - ivlen : saved_iv, ivlen);
    return ret;
#else
    return afalg_do_cipher(ctx, out, in, inl);
#endif
}

#if !defined(AFALG_KERNEL_UPDATES_CTR_IV) || !defined(AFALG_NO_FALLBACK)
static void ctr_update_iv(unsigned char *iv, size_t ivlen, __u64 nblocks)
{
    __be64 *a = (__be64 *)(iv + ivlen);
    __u64 b;

    for (; ivlen >= 8; ivlen -= 8) {
        b = nblocks + __be64_to_cpu(*--a);
        *a = __cpu_to_be64(b);
        if (nblocks < b)
            return;
        nblocks = 1;
    }
}
#endif

static int ctr_do_blocks(EVP_CIPHER_CTX *ctx, struct cipher_ctx *cipher_ctx,
                         unsigned char *out, const unsigned char *in,
                         size_t inl, size_t nblocks)
{
#if !defined(AFALG_KERNEL_UPDATES_CTR_IV) || !defined(AFALG_NO_FALLBACK)
    int ret;
    size_t ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);

    ret = afalg_do_cipher(ctx, out, in, inl);
    if (ret) {
        if (cipher_ctx->control_is_set) {
            ctr_update_iv(iv, ivlen, nblocks);
# ifndef AFALG_KERNEL_UPDATES_CTR_IV
            cipher_ctx->control_is_set = 0;
# endif
        } else {
# ifndef AFALG_NO_FALLBACK
            memcpy(iv, EVP_CIPHER_CTX_iv(cipher_ctx->fallback), ivlen);
# endif
        }
    }
    return ret;
#else
    (void)cipher_ctx;
    (void)nblocks;
    return afalg_do_cipher(ctx, out, in, inl);
#endif
}

static int ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t nblocks, len;

    /* handle initial partial block */
    while (cipher_ctx->num && inl) {
        (*out++) = *(in++) ^ cipher_ctx->partial[cipher_ctx->num];
        --inl;
        cipher_ctx->num = (cipher_ctx->num + 1) % cipher_ctx->blocksize;
    }

    /* process full blocks */
    if (inl >= (unsigned int) cipher_ctx->blocksize) {
        nblocks = inl / cipher_ctx->blocksize;
        len = nblocks * cipher_ctx->blocksize;
        if (!ctr_do_blocks(ctx, cipher_ctx, out, in, len, nblocks))
            return 0;
        inl -= len;
        out += len;
        in += len;
    }

    /* process final partial block */
    if (inl) {
        memset(cipher_ctx->partial, 0, cipher_ctx->blocksize);
        if (!ctr_do_blocks(ctx, cipher_ctx, cipher_ctx->partial,
                             cipher_ctx->partial, cipher_ctx->blocksize, 1))
            return 0;
        while (inl--) {
            out[cipher_ctx->num] = in[cipher_ctx->num]
                ^ cipher_ctx->partial[cipher_ctx->num];
            cipher_ctx->num++;
        }
    }

    return 1;
}

static int cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void* p2)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct cipher_ctx *to_cipher_ctx;

    (void)p1;
    switch (type) {

    case EVP_CTRL_COPY:
        if (cipher_ctx == NULL)
            return 1;
        /* when copying the context, a new session needs to be initialized */
        to_cipher_ctx = (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(
                        (EVP_CIPHER_CTX *)p2);

        to_cipher_ctx->bfd = to_cipher_ctx->sfd = -1;
        to_cipher_ctx->control_is_set = 0;
#ifdef AFALG_ZERO_COPY
        if (pipe(to_cipher_ctx->pipes) != 0)
            return 0;
#endif
#ifndef AFALG_NO_FALLBACK
        if (cipher_ctx->fallback) {
            if (!(to_cipher_ctx->fallback = EVP_CIPHER_CTX_new()))
                return 0;
            if (!EVP_CIPHER_CTX_copy(to_cipher_ctx->fallback,
                                     cipher_ctx->fallback)) {
                EVP_CIPHER_CTX_free(to_cipher_ctx->fallback);
                to_cipher_ctx->fallback = NULL;
                return 0;
            }
        }
#endif
        if ((to_cipher_ctx->bfd = dup(cipher_ctx->bfd)) == -1) {
            perror(__func__);
            return 0;
        }
        if ((to_cipher_ctx->sfd = accept(to_cipher_ctx->bfd, NULL, 0)) != -1)
            return 1;
        SYSerr(SYS_F_ACCEPT, errno);
#ifdef AFALG_ZERO_COPY
        close(to_cipher_ctx->pipes[0]);
        close(to_cipher_ctx->pipes[1]);
#endif
        return 0;

    case EVP_CTRL_INIT:
        cipher_ctx->bfd = cipher_ctx->sfd = -1;
        return 1;

    default:
        break;
    }

    return -1;
}

static int cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret;

    if (cipher_ctx == NULL)
        return 1;
#ifndef AFALG_NO_FALLBACK
    if (cipher_ctx->fallback) {
        EVP_CIPHER_CTX_free(cipher_ctx->fallback);
        cipher_ctx->fallback = NULL;
    }
#endif
    ret = !(0
#ifdef AFALG_ZERO_COPY
            | afalg_closefd(cipher_ctx->pipes[0])
            | afalg_closefd(cipher_ctx->pipes[1])
#endif
            | afalg_closefd(cipher_ctx->sfd)
            | afalg_closefd(cipher_ctx->bfd));

    cipher_ctx->bfd = cipher_ctx->sfd = -1;
    return ret;
}

/*
 * Keep tables of known nids, associated methods, selected ciphers, and driver
 * info.
 * Note that known_cipher_nids[] isn't necessarily indexed the same way as
 * cipher_data[] above, which the other tables are.
 */
static int known_cipher_nids[OSSL_NELEM(cipher_data)];
static int known_cipher_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_CIPHER *known_cipher_methods[OSSL_NELEM(cipher_data)] = { NULL, };
static int selected_ciphers[OSSL_NELEM(cipher_data)];
static struct driver_info_st cipher_driver_info[OSSL_NELEM(cipher_data)];

static int afalg_test_cipher(size_t cipher_data_index)
{
    return (cipher_driver_info[cipher_data_index].status == AFALG_STATUS_USABLE
            && selected_ciphers[cipher_data_index] == 1
            && (cipher_driver_info[cipher_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (cipher_driver_info[cipher_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void prepare_cipher_methods(void)
{
    size_t i;
    int fd, blocksize;
    int (*do_cipher) (EVP_CIPHER_CTX *, unsigned char *, const unsigned char *,
                      size_t);

    for (i = 0, known_cipher_nids_amount = 0;
         i < OSSL_NELEM(cipher_data); i++) {

        selected_ciphers[i] = 1;
        /*
         * Check that the cipher is usable
         */
        if ((fd =
            get_afalg_socket(cipher_data[i].name, "skcipher", 0, 0)) < 0) {
            cipher_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* test hardware acceleration */
        if ((fd =
            get_afalg_socket(cipher_data[i].name, "skcipher",
                             CRYPTO_ALG_KERN_DRIVER_ONLY,
                             CRYPTO_ALG_KERN_DRIVER_ONLY)) >= 0) {
            cipher_driver_info[i].accelerated = AFALG_ACCELERATED;
            close(fd);
        } else {
            cipher_driver_info[i].accelerated = AFALG_NOT_ACCELERATED;
        }

        blocksize = cipher_data[i].blocksize;
        switch (cipher_data[i].flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CBC_MODE:
            do_cipher = cbc_do_cipher;
            break;
        case EVP_CIPH_CTR_MODE:
            do_cipher = ctr_do_cipher;
            blocksize = 1;
            break;
        case EVP_CIPH_ECB_MODE:
            do_cipher = afalg_do_cipher;
            selected_ciphers[i] = 0;
            break;
        default:
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            known_cipher_methods[i] = NULL;
            continue;
        }

        if ((known_cipher_methods[i] =
                 EVP_CIPHER_meth_new(cipher_data[i].nid, blocksize,
                                     cipher_data[i].keylen)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(known_cipher_methods[i],
                                              cipher_data[i].ivlen)
            || !EVP_CIPHER_meth_set_flags(known_cipher_methods[i],
                                          cipher_data[i].flags
                                          | EVP_CIPH_CUSTOM_COPY
                                          | EVP_CIPH_CTRL_INIT
                                          | EVP_CIPH_FLAG_DEFAULT_ASN1)
            || !EVP_CIPHER_meth_set_init(known_cipher_methods[i], cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(known_cipher_methods[i], do_cipher)
            || !EVP_CIPHER_meth_set_ctrl(known_cipher_methods[i], cipher_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(known_cipher_methods[i],
                                            cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(known_cipher_methods[i],
                                                  sizeof(struct cipher_ctx))) {
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_CIPHER_meth_free(known_cipher_methods[i]);
            known_cipher_methods[i] = NULL;
        } else {
#ifndef AFALG_NO_FALLBACK
            if (cipher_data[i].fallback) {
                prepare_cipher_fallback(i, 0);
                prepare_cipher_fallback(i, 1);
                cipher_fb_threshold[i] = cipher_data[i].fb_threshold;
            }
#endif
            cipher_driver_info[i].status = AFALG_STATUS_USABLE;
            if (afalg_test_cipher(i))
                known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
        }
    }
}

static void rebuild_known_cipher_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_cipher_nids_amount = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (afalg_test_cipher(i))
            known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
    }
    ENGINE_unregister_ciphers(e);
    ENGINE_register_ciphers(e);
}

static const EVP_CIPHER *get_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_cipher_methods[i];
}

static int get_cipher_nids(const int **nids)
{
    *nids = known_cipher_nids;
    return known_cipher_nids_amount;
}

static void destroy_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    EVP_CIPHER_meth_free(known_cipher_methods[i]);
    known_cipher_methods[i] = NULL;
}

static void destroy_all_cipher_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        destroy_cipher_method(cipher_data[i].nid);
}

static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                             const int **nids, int nid)
{
    (void)e;
    if (cipher == NULL)
        return get_cipher_nids(nids);

    *cipher = get_cipher_method(nid);

    return *cipher != NULL;
}

static void afalg_select_all_ciphers(int *cipher_list, int include_ecb)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (include_ecb ||
           ((cipher_data[i].flags & EVP_CIPH_MODE) != EVP_CIPH_ECB_MODE))
            cipher_list[i] = 1;
       else
           cipher_list[i] = 0;
    }
}

static int afalg_select_cipher_cb(const char *str, int len, void *usr)
{
    int *cipher_list = (int *)usr;
    char *name, *fb;
    const EVP_CIPHER *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    /* Even thought it is useful only with fallback enabled, keep the check here
     * so that the same config file works with or without AFALG_NO_FALLBACK */
    if ((fb = index(name, ':'))) {
        *(fb) = '\0';
        fb++;
    }
    EVP = EVP_get_cipherbyname(name);
    if (EVP == NULL) {
        fprintf(stderr, "afalg: unknown cipher %s\n", name);
    } else if ((i = find_cipher_data_index(EVP_CIPHER_nid(EVP))) != (size_t)-1) {
        cipher_list[i] = 1;
#ifndef AFALG_NO_FALLBACK
        if (fb && (cipher_fb_threshold[i] = atoi(fb)) < 0) {
            cipher_fb_threshold[i] = cipher_data[i].fb_threshold;
        }
#endif
    } else {
        fprintf(stderr, "afalg: cipher %s not available\n", name);
    }
    OPENSSL_free(name);
    return 1;
}

static void dump_cipher_info(void)
{
    size_t i;
    const char *evp_name;
#ifndef AFALG_NO_CRYPTOUSER
    const char *driver_name;
#endif

    fprintf (stderr, "Information about ciphers supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        evp_name = OBJ_nid2sn(cipher_data[i].nid);
        fprintf (stderr, "Cipher %s, NID=%d, AF_ALG info: name=%s",
                 evp_name ? evp_name : "unknown", cipher_data[i].nid,
                 cipher_data[i].name);
        if (cipher_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, ". AF_ALG socket bind failed.\n");
            continue;
        }
#ifndef AFALG_NO_CRYPTOUSER
        /* gather hardware driver information */
        if (afalg_alg_list_count > 0) {
            driver_name =
                afalg_get_driver_name(cipher_data[i].name,
                                      cipher_driver_info[i].accelerated);
        } else {
            driver_name = "unknown";
        }
        fprintf(stderr, ", driver=%s", driver_name);
#endif
        if (cipher_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, " (hw accelerated)");
        else if (cipher_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, " (software)");
        else
            fprintf(stderr, " (acceleration status unknown)");
#ifndef AFALG_NO_FALLBACK
        if (cipher_data[i].fallback) {
            fprintf(stderr, ", sw fallback available, default threshold=%d",
                    cipher_data[i].fb_threshold);
        }
#endif
        if (cipher_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed.");
        fprintf (stderr, "\n");
    }
    fprintf(stderr, "\n");
}

#ifdef AFALG_DIGESTS
/******************************************************************************
 *
 * Digests
 *
 *****/

/* Cache up to this amount before sending the request to AF_ALG */
#ifndef AFALG_DIGEST_CACHE_SIZE
# define AFALG_DIGEST_CACHE_SIZE 16384
#endif

/* If the request is larger than this, send the current cache as is, then the
 * new request, instead of resizing the cache and sending it all at once
 */
#ifndef AFALG_DIGEST_CACHE_MAXSIZE
# define AFALG_DIGEST_CACHE_MAXSIZE 262144
#endif

struct digest_ctx {
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
#ifndef AFALG_NO_FALLBACK
    const EVP_MD_CTX *fallback;
    int fb_threshold;
    unsigned char res[EVP_MAX_MD_SIZE];
#endif
    const struct digest_data_st *digest_d;
    size_t inp_len;
    void *inp_data;
};

static const struct digest_data_st {
    int nid;
    int blocksize;
    int digestlen;
    char *name;
#ifndef AFALG_NO_FALLBACK
    const EVP_MD *((*fallback) (void));
    int fb_threshold;
#endif
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, /* MD5_CBLOCK */ 64, 16, "md5",
#ifndef AFALG_NO_FALLBACK
      EVP_md5, 16384
#endif
    },
#endif
    { NID_sha1, SHA_CBLOCK, 20, "sha1",
#ifndef AFALG_NO_FALLBACK
      EVP_sha1, 16384
#endif
    },
#ifndef OPENSSL_NO_RMD160
    { NID_ripemd160, /* RIPEMD160_CBLOCK */ 64, 20, "rmd160",
#ifndef AFALG_NO_FALLBACK
      EVP_ripemd160, 16384
#endif
    },
#endif
    { NID_sha224, SHA256_CBLOCK, 224 / 8, "sha224",
#ifndef AFALG_NO_FALLBACK
      EVP_sha224, 16384
#endif
    },
    { NID_sha256, SHA256_CBLOCK, 256 / 8, "sha256",
#ifndef AFALG_NO_FALLBACK
      EVP_sha256, 16384
#endif
    },
    { NID_sha384, SHA512_CBLOCK, 384 / 8, "sha384",
#ifndef AFALG_NO_FALLBACK
      EVP_sha384, 16384
#endif
    },
    { NID_sha512, SHA512_CBLOCK, 512 / 8, "sha512",
#ifndef AFALG_NO_FALLBACK
      EVP_sha512, 16384
#endif
    },
};

static size_t find_digest_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        if (nid == digest_data[i].nid)
            return i;
    return (size_t)-1;
}

static size_t get_digest_data_index(int nid)
{
    size_t i = find_digest_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

#ifndef AFALG_NO_FALLBACK
static EVP_MD_CTX *digest_fb_ctx[OSSL_NELEM(digest_data)] = { NULL, };
static int digest_fb_threshold[OSSL_NELEM(cipher_data)] = { 0, };

static int digest_use_fb(const EVP_MD_CTX *fallback, const void *data,
                         size_t len, unsigned char *res)
{
    EVP_MD_CTX *new_ctx = EVP_MD_CTX_new();
    int ret;

    if (!new_ctx)
        return 0;

    ret = EVP_MD_CTX_copy(new_ctx, fallback)
        && EVP_DigestUpdate(new_ctx, data, len)
        && EVP_DigestFinal_ex(new_ctx, res, NULL);

    EVP_MD_CTX_free(new_ctx);
    return ret;
}
#endif

static int digest_init(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int i = get_digest_data_index(EVP_MD_CTX_type(ctx));

    digest_ctx->sfd = -1;
    digest_ctx->digest_d = &digest_data[i];
#ifndef AFALG_NO_FALLBACK
    if (digest_fb_ctx[i]) {
        digest_ctx->fallback = digest_fb_ctx[i];
        digest_ctx->fb_threshold = digest_fb_threshold[i];
    }
#endif
    return 1;
}

static int digest_get_sfd(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    __u32 afalg_mask;
    const struct digest_data_st *digest_d = digest_ctx->digest_d;

    digest_ctx->sfd = -1;
    if (use_softdrivers == AFALG_REQUIRE_ACCELERATED)
        afalg_mask = CRYPTO_ALG_KERN_DRIVER_ONLY;
    else
        afalg_mask = 0;
    digest_ctx->bfd = get_afalg_socket(digest_d->name, "hash",
                                       afalg_mask, afalg_mask);
    if (digest_ctx->bfd < 0) {
        SYSerr(SYS_F_BIND, errno);
        return 0;
    }
    if ((digest_ctx->sfd = accept(digest_ctx->bfd, NULL, 0)) < 0)
        goto out;
#ifdef AFALG_ZERO_COPY
    if (pipe(digest_ctx->pipes) != 0)
        goto out;
#endif
    return 1;
out:
    close(digest_ctx->bfd);
    digest_ctx->bfd = -1;
    if (digest_ctx->sfd > -1) {
        close(digest_ctx->sfd);
        digest_ctx->sfd = -1;
    }
    return 0;
}

static int afalg_do_digest(EVP_MD_CTX *ctx, const void *data, size_t len,
                           int more)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int flags;
#ifdef AFALG_ZERO_COPY
    struct iovec iov;
    int use_zc = (len <= zc_maxsize) && (((size_t)data & pagemask) == 0);
#endif
#ifndef AFALG_NO_FALLBACK
    if (digest_ctx->sfd == -1 && digest_ctx->fallback && !more
        && len < digest_ctx->fb_threshold
        && digest_use_fb(digest_ctx->fallback, data, len, digest_ctx->res))
           return 1;
#endif
    if (digest_ctx->sfd == -1 && !digest_get_sfd(ctx))
        return 0;
#ifdef AFALG_ZERO_COPY
    if (use_zc) {
        iov.iov_base = (void *)data;
        iov.iov_len = len;
        flags = SPLICE_F_GIFT & (more ? SPLICE_F_MORE : 0);
        return vmsplice(digest_ctx->pipes[1], &iov, 1, flags) == (ssize_t) len
            && splice(digest_ctx->pipes[0], NULL, digest_ctx->sfd, NULL, len,
                      flags) == (ssize_t) len;
    }
#endif
    flags = more ? MSG_MORE : 0;
    return send(digest_ctx->sfd, data, len, flags) == (ssize_t) len;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    char *new_data;
    int ret = 0;

    if (len == 0)
        return 1;
    if (digest_ctx == NULL)
        return 0;
    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT))
        return afalg_do_digest(ctx, data, len, 0);
    if (digest_ctx->inp_len == 0 && len >= AFALG_DIGEST_CACHE_SIZE)
        return afalg_do_digest(ctx, data, len, 1);
    if (len > AFALG_DIGEST_CACHE_MAXSIZE) {
        if (!afalg_do_digest(ctx, digest_ctx->inp_data,
                             digest_ctx->inp_len, 1))
            return 0;
        ret = afalg_do_digest(ctx, data, len, 1);
        goto reset_data;
    }
    new_data = OPENSSL_realloc(digest_ctx->inp_data,
                               digest_ctx->inp_len + len);
    if (!new_data) {
        perror(__func__);
        return 0;
    }
    memcpy(new_data + digest_ctx->inp_len, data, len);
    digest_ctx->inp_len += len;
    digest_ctx->inp_data = new_data;
    if (digest_ctx->inp_len < AFALG_DIGEST_CACHE_SIZE)
        return 1;
    ret = afalg_do_digest(ctx, digest_ctx->inp_data, digest_ctx->inp_len, 1);

reset_data:
    OPENSSL_free(digest_ctx->inp_data);
    digest_ctx->inp_data = NULL;
    digest_ctx->inp_len = 0;
    return ret;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int len = EVP_MD_CTX_size(ctx);
    int ret = 0;

    if (digest_ctx == NULL)
        return 0;
    if (md == NULL)
        goto out;

    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT)
        || afalg_do_digest(ctx, digest_ctx->inp_data,
                           digest_ctx->inp_len, 0)) {
        if (digest_ctx->sfd != -1) {
            ret = recv(digest_ctx->sfd, md, len, 0) == len;
        } else {
#ifndef AFALG_NO_FALLBACK
            memcpy(md, digest_ctx->res, len);
            ret = 1;
#endif
        }
    }

out:
    OPENSSL_free(digest_ctx->inp_data);
    digest_ctx->inp_data = NULL;
    digest_ctx->inp_len = 0;
    return ret;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);

    if (digest_from == NULL)
        return 1;
    if (digest_from->inp_len > 0) {
        digest_to->inp_data = OPENSSL_malloc(digest_from->inp_len);
        if (digest_to->inp_data == NULL) {
           perror(__func__);
           digest_to->inp_len = 0;
           return 0;
        }
        memcpy(digest_to->inp_data, digest_from->inp_data,
               digest_from->inp_len);
    }
    if (digest_from->sfd == -1)
        return 1;
    digest_to->sfd = digest_to->bfd = -1;
#ifdef AFALG_ZERO_COPY
    if (pipe(digest_to->pipes) != 0)
        return 0;
#endif
    if ((digest_to->bfd = dup(digest_from->bfd)) == -1) {
        perror(__func__);
        goto fail;
    }
    if ((digest_to->sfd = accept(digest_from->sfd, NULL, 0)) != -1)
        return 1;

    SYSerr(SYS_F_ACCEPT, errno);
fail:
#ifdef AFALG_ZERO_COPY
    close(digest_to->pipes[0]);
    close(digest_to->pipes[1]);
#endif
    if (digest_to->bfd != -1)
        close(digest_to->bfd);
    digest_to->sfd = digest_to->bfd = -1;
    return 0;
}

static int digest_cleanup(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (digest_ctx == NULL || digest_ctx->sfd == -1)
        return 1;

    return !(0
#ifdef AFALG_ZERO_COPY
             | afalg_closefd(digest_ctx->pipes[0])
             | afalg_closefd(digest_ctx->pipes[1])
#endif
             | afalg_closefd(digest_ctx->sfd)
             | afalg_closefd(digest_ctx->bfd));
}

/*
 * Keep tables of known nids, associated methods, selected digests, and
 * driver info.
 * Note that known_digest_nids[] isn't necessarily indexed the same way as
 * digest_data[] above, which the other tables are.
 */
static int known_digest_nids[OSSL_NELEM(digest_data)];
static int known_digest_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_MD *known_digest_methods[OSSL_NELEM(digest_data)] = { NULL, };
static int selected_digests[OSSL_NELEM(digest_data)];
static struct driver_info_st digest_driver_info[OSSL_NELEM(digest_data)];

#ifndef AFALG_NO_FALLBACK
static EVP_MD_CTX *get_digest_fb_ctx(const EVP_MD *type)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx || EVP_DigestInit_ex(ctx, type, NULL))
        return ctx;
    EVP_MD_CTX_free(ctx);
    return NULL;
}
#endif

static int afalg_test_digest(size_t digest_data_index)
{
    return (digest_driver_info[digest_data_index].status == AFALG_STATUS_USABLE
            && selected_digests[digest_data_index] == 1
            && (digest_driver_info[digest_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (digest_driver_info[digest_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void rebuild_known_digest_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data); i++) {
        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
    ENGINE_unregister_digests(e);
    ENGINE_register_digests(e);
}

static void prepare_digest_methods(void)
{
    size_t i;
    int fd;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data);
         i++) {

        selected_digests[i] = 0;
        /*
         * Check that the digest is usable
         */
        if ((fd = get_afalg_socket(digest_data[i].name, "hash", 0, 0)) < 0) {
            digest_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* test hardware acceleration */
        if ((fd =
            get_afalg_socket(digest_data[i].name, "hash",
                             CRYPTO_ALG_KERN_DRIVER_ONLY,
                             CRYPTO_ALG_KERN_DRIVER_ONLY)) >= 0) {
            digest_driver_info[i].accelerated = AFALG_ACCELERATED;
            close(fd);
        } else {
            digest_driver_info[i].accelerated = AFALG_NOT_ACCELERATED;
        }

        if ((known_digest_methods[i] = EVP_MD_meth_new(digest_data[i].nid,
                                                       NID_undef)) == NULL
            || !EVP_MD_meth_set_input_blocksize(known_digest_methods[i],
                                                digest_data[i].blocksize)
            || !EVP_MD_meth_set_result_size(known_digest_methods[i],
                                            digest_data[i].digestlen)
            || !EVP_MD_meth_set_init(known_digest_methods[i], digest_init)
            || !EVP_MD_meth_set_update(known_digest_methods[i], digest_update)
            || !EVP_MD_meth_set_final(known_digest_methods[i], digest_final)
            || !EVP_MD_meth_set_copy(known_digest_methods[i], digest_copy)
            || !EVP_MD_meth_set_cleanup(known_digest_methods[i], digest_cleanup)
            || !EVP_MD_meth_set_app_datasize(known_digest_methods[i],
                                             sizeof(struct digest_ctx))) {
            digest_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_MD_meth_free(known_digest_methods[i]);
            known_digest_methods[i] = NULL;
        } else {
#ifndef AFALG_NO_FALLBACK
            if (digest_data[i].fallback) {
                digest_fb_ctx[i] = get_digest_fb_ctx(digest_data[i].fallback());
                digest_fb_threshold[i] = digest_data[i].fb_threshold;
            }
#endif
            digest_driver_info[i].status = AFALG_STATUS_USABLE;
        }
        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
}

static const EVP_MD *get_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_digest_methods[i];
}

static void destroy_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    EVP_MD_meth_free(known_digest_methods[i]);
    known_digest_methods[i] = NULL;
}

static void destroy_all_digest_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        destroy_digest_method(digest_data[i].nid);
}

static int afalg_digests(ENGINE *e, const EVP_MD **digest,
                             const int **nids, int nid)
{
    (void)e;
    if (digest == NULL) {
        *nids = known_digest_nids;
        return known_digest_nids_amount;
    }
    *digest = get_digest_method(nid);

    return *digest != NULL;
}

static void afalg_select_all_digests(int *digest_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        digest_list[i] = 1;
}

static int afalg_select_digest_cb(const char *str, int len, void *usr)
{
    int *digest_list = (int *)usr;
    char *name, *fb;
    const EVP_MD *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    /* Even thought it is useful only with fallback enabled, keep the check here
     * so that the same config file works with or without AFALG_NO_FALLBACK */
    if ((fb = index(name, ':'))) {
        *(fb) = '\0';
        fb++;
    }
    EVP = EVP_get_digestbyname(name);
    if (EVP == NULL) {
        fprintf(stderr, "afalg: unknown digest %s\n", name);
    } else if ((i = find_digest_data_index(EVP_MD_type(EVP))) != (size_t)-1) {
        digest_list[i] = 1;
#ifndef AFALG_NO_FALLBACK
        if (fb && (digest_fb_threshold[i] = atoi(fb)) < 0) {
            digest_fb_threshold[i] = digest_data[i].fb_threshold;
        }
#endif
    } else {
        fprintf(stderr, "afalg: digest %s not available\n", name);
    }
    OPENSSL_free(name);
    return 1;
}

static void dump_digest_info(void)
{
    size_t i;
    const char *evp_name;
#ifndef AFALG_NO_CRYPTOUSER
    const char *driver_name;
#endif

    fprintf (stderr, "Information about digests supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        evp_name = OBJ_nid2sn(digest_data[i].nid);
        fprintf (stderr, "Digest %s, NID=%d, AF_ALG info: name=%s",
                 evp_name ? evp_name : "unknown", digest_data[i].nid,
                 digest_data[i].name);
        if (digest_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, ". AF_ALG socket bind failed.\n");
            continue;
        }
#ifndef AFALG_NO_CRYPTOUSER
        /* gather hardware driver information */
        if (afalg_alg_list_count > 0) {
            driver_name =
                afalg_get_driver_name(digest_data[i].name,
                                      digest_driver_info[i].accelerated);
        } else {
            driver_name = "unknown";
        }
        fprintf(stderr, ", driver=%s", driver_name);
#endif
        if (digest_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, " (hw accelerated)");
        else if (digest_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, " (software)");
        else
            fprintf(stderr, " (acceleration status unknown)");
        if (digest_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Digest setup failed.");
        fprintf (stderr, "\n");
    }
    fprintf(stderr, "\n");
}

#endif /* AFALG_DIGESTS */

/******************************************************************************
 *
 * CONTROL COMMANDS
 *
 *****/

enum {
    AFALG_CMD_USE_SOFTDRIVERS = ENGINE_CMD_BASE,
    AFALG_CMD_CIPHERS,
#ifdef AFALG_DIGESTS
    AFALG_CMD_DIGESTS,
#endif
    AFALG_CMD_DUMP_INFO
};

/* Helper macros for CPP string composition */
#ifndef OPENSSL_MSTR
# define OPENSSL_MSTR_HELPER(x) #x
# define OPENSSL_MSTR(x) OPENSSL_MSTR_HELPER(x)
#endif

static const ENGINE_CMD_DEFN afalg_cmds[] = {
    {AFALG_CMD_USE_SOFTDRIVERS,
    "USE_SOFTDRIVERS",
    "specifies whether to use software (not accelerated) drivers ("
        OPENSSL_MSTR(AFALG_REQUIRE_ACCELERATED) "=use only accelerated drivers, "
        OPENSSL_MSTR(AFALG_USE_SOFTWARE) "=allow all drivers, "
        OPENSSL_MSTR(AFALG_REJECT_SOFTWARE)
        "=use if acceleration can't be determined) [default="
        OPENSSL_MSTR(AFALG_DEFAULT_USE_SOFTDRIVERS) "]",
    ENGINE_CMD_FLAG_NUMERIC},

    {AFALG_CMD_CIPHERS,
     "CIPHERS",
     "either ALL, NONE, NO_ECB (all except ECB-mode) or a comma-separated"
     " list of ciphers to enable"
#ifndef AFALG_NO_FALLBACK
     ". If you use a list, each cipher may be followed by a colon (:) and the"
     " minimum request length to use AF_ALG drivers for that cipher; smaller"
     " requests are processed by softare; a negative value will use the"
     " default for that cipher; use DUMP_INFO to see the ciphers that support"
     " software fallback, and their default values"
#endif
     " [default=NO_ECB]",
     ENGINE_CMD_FLAG_STRING},

#ifdef AFALG_DIGESTS
   {AFALG_CMD_DIGESTS,
     "DIGESTS",
     "either ALL, NONE, or a comma-separated list of digests to enable"
#ifndef AFALG_NO_FALLBACK
     ". If you use a list, each digest may be followed by a colon (:) and the"
     " minimum request length to use AF_ALG drivers for that digest; a negative"
     " value will use the default (16384) for that digest"
#endif
     " [default=NONE]",
     ENGINE_CMD_FLAG_STRING},
#endif

   {AFALG_CMD_DUMP_INFO,
     "DUMP_INFO",
     "dump info about each algorithm to stderr; use 'openssl engine -pre DUMP_INFO afalg'",
     ENGINE_CMD_FLAG_NO_INPUT},

    {0, NULL, NULL, 0}
};

static int afalg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int *new_list;

    (void)e;
    (void)f;
    switch(cmd) {
    case AFALG_CMD_USE_SOFTDRIVERS:
        switch(i) {
        case AFALG_REQUIRE_ACCELERATED:
        case AFALG_USE_SOFTWARE:
        case AFALG_REJECT_SOFTWARE:
            break;
        default:
            fprintf(stderr, "afalg: invalid value (%ld) for USE_SOFTDRIVERS\n", i);
            return 0;
        }
        if (use_softdrivers == i)
            return 1;
        use_softdrivers = i;
#ifdef AFALG_DIGESTS
        rebuild_known_digest_nids(e);
#endif
        rebuild_known_cipher_nids(e);
        return 1;

    case AFALG_CMD_CIPHERS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "NO_ECB") == 0) {
            afalg_select_all_ciphers(selected_ciphers, 0);
        } else if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_ciphers(selected_ciphers, 1);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_ciphers, 0, sizeof(selected_ciphers));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_ciphers));
            if (!CONF_parse_list(p, ',', 1, afalg_select_cipher_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_ciphers, new_list, sizeof(selected_ciphers));
            OPENSSL_free(new_list);
        }
        rebuild_known_cipher_nids(e);
        return 1;

#ifdef AFALG_DIGESTS
    case AFALG_CMD_DIGESTS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_digests(selected_digests);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_digests, 0, sizeof(selected_digests));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_digests));
            if (!CONF_parse_list(p, ',', 1, afalg_select_digest_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_digests, new_list, sizeof(selected_digests));
            OPENSSL_free(new_list);
        }
        rebuild_known_digest_nids(e);
        return 1;
#endif

    case AFALG_CMD_DUMP_INFO:
#ifndef AFALG_NO_CRYPTOUSER
        prepare_afalg_alg_list();
        if (afalg_alg_list_count < 0)
            fprintf (stderr, "Could not get driver info through the netlink"
                     " interface.\nIs the 'crypto_user' module loaded?\n");
#endif
        dump_cipher_info();
#ifdef AFALG_DIGESTS
        dump_digest_info();
#endif
        return 1;

    default:
        break;
    }
    return 0;
}

/******************************************************************************
 *
 * LOAD / UNLOAD
 *
 *****/

static int afalg_unload(ENGINE *e)
{
    (void)e;
    destroy_all_cipher_methods();
#ifdef AFALG_DIGESTS
    destroy_all_digest_methods();
#endif

    return 1;
}


static int bind_afalg(ENGINE *e) {
    int ret;

    if (!ENGINE_set_id(e, engine_afalg_id)
        || !ENGINE_set_name(e, "AF_ALG engine")
        || !ENGINE_set_destroy_function(e, afalg_unload)
        || !ENGINE_set_cmd_defns(e, afalg_cmds)
        || !ENGINE_set_ctrl_function(e, afalg_ctrl))
        return 0;

#ifdef AFALG_ZERO_COPY
    pagemask = sysconf(_SC_PAGESIZE) - 1;
    zc_maxsize = sysconf(_SC_PAGESIZE) * 16;
#endif
    prepare_cipher_methods();
#ifdef AFALG_DIGESTS
    prepare_digest_methods();
#endif
    OPENSSL_free(afalg_alg_list);
    if (afalg_alg_list_count > 0)
        afalg_alg_list_count = 0;
    ret = ENGINE_set_ciphers(e, afalg_ciphers);
#ifdef AFALG_DIGESTS
    ret = ret && ENGINE_set_digests(e, afalg_digests);
#endif
    return ret;
}

static int test_afalg_socket(void)
{
    int sock;

    /* Test if we can actually create an AF_ALG socket */
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        fprintf(stderr, "Could not create AF_ALG socket: %s\n", strerror(errno));
        return 0;
    }
    close(sock);
    return 1;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if ((id && (strcmp(id, engine_afalg_id) != 0))
        || !test_afalg_socket())
        return 0;
    if (!bind_afalg(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
