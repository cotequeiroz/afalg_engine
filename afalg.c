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
 */

#ifdef AFALG_ZERO_COPY
/* Required for vmsplice */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# include <sys/uio.h>

static size_t zc_maxsize, pagemask;
#endif

#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>
#include <asm/types.h>
#ifndef AFALG_NO_CRYPTOUSER
# include <linux/cryptouser.h>
#elif !defined(CRYPTO_MAX_NAME)
# define CRYPTO_MAX_NAME 64
#endif
#include <linux/if_alg.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
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

    char *driver_name;
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
            else if (msg_len == 0)
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

static enum afalg_accelerated_t
afalg_get_accel_info(const char *alg_name, char *driver_name, size_t driver_len)
{
    int i;
    __u32 priority = 0;
    int found = 0;
    enum afalg_accelerated_t new_accel, cur_accel = AFALG_ACCELERATION_UNKNOWN;

    for (i = 0; i < afalg_alg_list_count; i++) {
        if (strcmp(afalg_alg_list[i].alg_name, alg_name) ||
            priority > afalg_alg_list[i].priority)
            continue;
        if (afalg_alg_list[i].flags & CRYPTO_ALG_KERN_DRIVER_ONLY)
            new_accel = AFALG_ACCELERATED;
        else
            new_accel = AFALG_NOT_ACCELERATED;
        if (found && priority == afalg_alg_list[i].priority) {
            OPENSSL_strlcpy(driver_name, "**unreliable info**", driver_len);
            if (new_accel != cur_accel)
                cur_accel = AFALG_ACCELERATION_UNKNOWN;
        } else {
            found = 1;
            cur_accel = new_accel;
            priority = afalg_alg_list[i].priority;
            OPENSSL_strlcpy(driver_name, afalg_alg_list[i].driver_name,
                            driver_len);
        }
    }
    return cur_accel;
}

/******************************************************************************
 *
 * Ciphers
 *
 *****/

struct cipher_ctx {
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
    unsigned int blocksize, num;
    unsigned char partial[EVP_MAX_BLOCK_LENGTH];
};

static const struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    const char *name;
} cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, "cbc(des)" },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, "cbc(des3_ede)" },
#endif
#ifndef OPENSSL_NO_BF
    { NID_bf_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(blowfish)" },
#endif
#ifndef OPENSSL_NO_CAST
    { NID_cast5_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(cast5)" },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
    { NID_aes_128_ecb, 16, 128 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
    { NID_aes_192_ecb, 16, 192 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
    { NID_aes_256_ecb, 16, 256 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
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

static const struct cipher_data_st *get_cipher_data(int nid)
{
    return &cipher_data[get_cipher_data_index(nid)];
}

static int afalg_set_key(int sfd, const void *key, int keylen)
{
    if (setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, keylen) >= 0)
        return 1;
    SYSerr(SYS_F_SETSOCKOPT, errno);
    return 0;
}

static void afalg_set_op(struct cmsghdr *cmsg, unsigned int op)
{
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(op));
    *(CMSG_DATA(cmsg)) = op;
}

static void afalg_set_iv(struct cmsghdr *cmsg, const unsigned char *iv, unsigned int ivlen)
{
    struct af_alg_iv *aiv;

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
    aiv = (void *)CMSG_DATA(cmsg);
    aiv->ivlen = ivlen;
    memcpy(aiv->iv, iv, ivlen);
}

static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    const struct cipher_data_st *cipher_d =
        get_cipher_data(EVP_CIPHER_CTX_nid(ctx));
    int keylen;
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    int op = enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    size_t set_op_len = sizeof(op);
    size_t ivlen = (iv == NULL) ? 0 : EVP_CIPHER_CTX_iv_length(ctx);
    size_t set_iv_len = offsetof(struct af_alg_iv, iv) + ivlen;
    size_t controllen = CMSG_SPACE(set_op_len)
                        + (ivlen > 0 ? CMSG_SPACE(set_iv_len) : 0);
    __u32 afalg_mask;

    if (cipher_ctx->bfd == -1) {
        if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CTR_MODE)
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
    } else {
        close(cipher_ctx->sfd);
        cipher_ctx->sfd = -1;
    }
    if (key != NULL
        && (keylen = EVP_CIPHER_CTX_key_length(ctx)) > 0
        && !afalg_set_key(cipher_ctx->bfd, key, keylen)) {
        fprintf(stderr, "cipher_init: Error setting key.\n");
        goto err;
    }
    if ((cipher_ctx->sfd = accept(cipher_ctx->bfd, NULL, 0)) < 0) {
        perror("cipher_init: accept");
        goto err;
    }
    if ((msg.msg_control = OPENSSL_zalloc(controllen)) == NULL) {
        perror("cipher_init: OPENSSL_zalloc");
        goto err_close;
    }
    msg.msg_controllen = controllen;
    if ((cmsg = CMSG_FIRSTHDR(&msg)) == NULL) {
        fprintf(stderr, "cipher_init: CMSG_FIRSTHDR error setting op.\n");
        goto err;
    }
    afalg_set_op(cmsg, op);
    if (ivlen > 0) {
        if ((cmsg = CMSG_NXTHDR(&msg, cmsg)) == NULL)
            goto err;
        afalg_set_iv(cmsg, iv, ivlen);
    }
    if (sendmsg(cipher_ctx->sfd, &msg, 0) < 0) {
        perror("cipher_init: sendmsg");
        goto err;
    }
#ifdef AFALG_ZERO_COPY
    if (pipe(cipher_ctx->pipes) < 0) {
        perror("cipher_init: pipes");
        goto err;
    }
#endif
    return 1;

err:
    free(msg.msg_control);
err_close:
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
    ssize_t ret = -1;
#ifdef AFALG_ZERO_COPY
    struct iovec iov;
    int use_zc = (inl <= zc_maxsize) && (((size_t)in & pagemask) == 0);

    if (use_zc) {
        iov.iov_base = (void *)in;
	iov.iov_len = inl;
        ret = vmsplice(cipher_ctx->pipes[1], &iov, 1,
                       SPLICE_F_GIFT & SPLICE_F_MORE);
        if (ret < 0) {
            perror("afalg_do_cipher: vmsplice");
            goto err;
        } else if (ret != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: vmsplice: sent %zd bytes != len %zd\n",
                    ret, inl);
            goto err;
        }
        ret = splice(cipher_ctx->pipes[0], NULL, cipher_ctx->sfd, NULL, inl, 0);
        if (ret < 0) {
            perror("afalg_do_cipher: splice");
            goto err;
        } else if (ret != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: splice: spliced %zd bytes != len %zd\n",
                    ret, inl);
            goto err;
        }
    } else
#endif
    {
        if ((ret = send(cipher_ctx->sfd, in, inl, MSG_MORE)) < 0) {
            perror("afalg_do_cipher: send");
            goto err;
        } else if (ret != (ssize_t) inl) {
            fprintf(stderr, "afalg_do_cipher: sent %zd bytes != len %zd\n",
                    ret, inl);
            goto err;
        }
    }
    if ((ret = read(cipher_ctx->sfd, out, inl)) == (ssize_t) inl)
        return 1;

    fprintf(stderr, "afalg_do_cipher: read %zd bytes != len %zd\n",
            ret, inl);

err:
    return 0;
}

static void ctr_updateiv(unsigned char* iv, size_t ivlen, size_t nblocks)
{
#ifndef AFALG_KERNEL_UPDATES_IV
    do {
        ivlen--;
        nblocks += iv[ivlen];
        iv[ivlen] = (uint8_t) nblocks;
        nblocks >>= 8;
    } while (ivlen);
#else
    (void)iv;
    (void)ivlen;
    (void)nblocks;
#endif
}

static int ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t ivlen = EVP_CIPHER_CTX_iv_length(ctx), nblocks, len;
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);

    /* handle initial partial block */
    while (cipher_ctx->num && inl) {
        (*out++) = *(in++) ^ cipher_ctx->partial[cipher_ctx->num];
        --inl;
        cipher_ctx->num = (cipher_ctx->num + 1) % cipher_ctx->blocksize;
    }

    /* process full blocks */
    if (inl > (unsigned int) cipher_ctx->blocksize) {
      nblocks = inl/cipher_ctx->blocksize;
      len = nblocks * cipher_ctx->blocksize;
      if (afalg_do_cipher(ctx, out, in, len) < 1)
          return 0;
      ctr_updateiv(iv, ivlen, nblocks);
      inl -= len;
      out += len;
      in += len;
    }

    /* process final partial block */
    if (inl) {
        memset(cipher_ctx->partial, 0, cipher_ctx->blocksize);
        if (afalg_do_cipher(ctx, cipher_ctx->partial, cipher_ctx->partial,
                            cipher_ctx->blocksize) < 1)
            return 0;
        ctr_updateiv(iv, ivlen, 1);
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
#ifdef AFALG_ZERO_COPY
        if (pipe(to_cipher_ctx->pipes) != 0)
            return 0;
#endif
        if ((to_cipher_ctx->bfd = accept(cipher_ctx->bfd, NULL, 0)) != -1
            && (to_cipher_ctx->sfd = accept(to_cipher_ctx->bfd, NULL, 0)) != -1)
            return 1;
        SYSerr(SYS_F_ACCEPT, errno);
#ifdef AFALG_ZERO_COPY
        close(to_cipher_ctx->pipes[0]);
        close(to_cipher_ctx->pipes[1]);
#endif
        if (to_cipher_ctx->bfd >= 0)
            close(to_cipher_ctx->bfd);
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

        /* gather hardware driver information */
        if (afalg_alg_list_count > 0
            && (cipher_driver_info[i].driver_name =
                OPENSSL_zalloc(CRYPTO_MAX_NAME)) != NULL
            && cipher_driver_info[i].accelerated !=
               afalg_get_accel_info(cipher_data[i].name,
                                    cipher_driver_info[i].driver_name,
                                    CRYPTO_MAX_NAME)) {
            OPENSSL_strlcpy(cipher_driver_info[i].driver_name,
                            "**unreliable info**", CRYPTO_MAX_NAME);
            cipher_driver_info[i].accelerated = AFALG_ACCELERATION_UNKNOWN;
        }
        blocksize = cipher_data[i].blocksize;
        switch (cipher_data[i].flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CBC_MODE:
            do_cipher = afalg_do_cipher;
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

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        destroy_cipher_method(cipher_data[i].nid);
        OPENSSL_free(cipher_driver_info[i].driver_name);
        cipher_driver_info[i].driver_name = NULL;
    }
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
    char *name;
    const EVP_CIPHER *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    EVP = EVP_get_cipherbyname(name);
    if (EVP == NULL)
        fprintf(stderr, "afalg: unknown cipher %s\n", name);
    else if ((i = find_cipher_data_index(EVP_CIPHER_nid(EVP))) != (size_t)-1)
        cipher_list[i] = 1;
    else
        fprintf(stderr, "afalg: cipher %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_cipher_info(void)
{
    size_t i;
    const char *evp_name;

    fprintf (stderr, "Information about ciphers supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        evp_name = OBJ_nid2sn(cipher_data[i].nid);
        fprintf (stderr, "Cipher %s, NID=%d, AF_ALG info: name=%s, ",
                 evp_name ? evp_name : "unknown", cipher_data[i].nid,
                 cipher_data[i].name);
        if (cipher_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, "AF_ALG socket bind failed.\n");
            continue;
        }
        fprintf(stderr, " driver=%s ", cipher_driver_info[i].driver_name ?
                 cipher_driver_info[i].driver_name : "unknown");
        if (cipher_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, "(hw accelerated)");
        else if (cipher_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, "(software)");
        else
            fprintf(stderr, "(acceleration status unknown)");
        if (cipher_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed.");
        fprintf (stderr, "\n");
    }
    fprintf(stderr, "\n");
}

/******************************************************************************
 *
 * Digests
 *
 *****/

struct digest_ctx {
    /* This signals that the init function was called, not that it succeeded. */
    int init_called;
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
};

static const struct digest_data_st {
    int nid;
    int blocksize;
    int digestlen;
    char *name;
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, /* MD5_CBLOCK */ 64, 16, "md5" },
#endif
    { NID_sha1, SHA_CBLOCK, 20, "sha1" },
#ifndef OPENSSL_NO_RMD160
    { NID_ripemd160, /* RIPEMD160_CBLOCK */ 64, 20, "rmd160" },
#endif
    { NID_sha224, SHA256_CBLOCK, 224 / 8, "sha224" },
    { NID_sha256, SHA256_CBLOCK, 256 / 8, "sha256" },
    { NID_sha384, SHA512_CBLOCK, 384 / 8, "sha384" },
    { NID_sha512, SHA512_CBLOCK, 512 / 8, "sha512" },
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

static const struct digest_data_st *get_digest_data(int nid)
{
    return &digest_data[get_digest_data_index(nid)];
}

static int digest_init(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    const struct digest_data_st *digest_d =
        get_digest_data(EVP_MD_CTX_type(ctx));
    __u32 afalg_mask;

    digest_ctx->init_called = 1;

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
    if ((digest_ctx->sfd = accept(digest_ctx->bfd, NULL, 0)) >= 0
#ifdef AFALG_ZERO_COPY
        && pipe(digest_ctx->pipes) == 0
#endif
        )
        return 1;
    close(digest_ctx->bfd);
    digest_ctx->bfd = -1;
    if (digest_ctx->sfd > -1) {
        close(digest_ctx->sfd);
        digest_ctx->sfd = -1;
    }
    return 0;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int flags;
#ifdef AFALG_ZERO_COPY
    struct iovec iov;
    int use_zc = (count <= zc_maxsize) && (((size_t)data & pagemask) == 0);
#endif

    if (count == 0)
        return 1;

    if (digest_ctx == NULL)
        return 0;

#ifdef AFALG_ZERO_COPY
    if (use_zc) {
        iov.iov_base = (void *)data;
        iov.iov_len = count;

        if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT))
            flags = SPLICE_F_GIFT;
        else
            flags = SPLICE_F_MORE | SPLICE_F_GIFT;

        if (vmsplice(digest_ctx->pipes[1], &iov, 1, flags) >=0
            && splice(digest_ctx->pipes[0], NULL, digest_ctx->sfd, NULL,
                      count, flags) >0)
            return 1;
    }
    else
#endif
    {
        if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT))
            flags = 0;
        else
            flags = MSG_MORE;

        if (send(digest_ctx->sfd, data, count, flags) == (ssize_t)count)
            return 1;
    }
    return 0;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int len = EVP_MD_CTX_size(ctx);

    if (md == NULL || digest_ctx == NULL)
        return 0;

    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT)
        && send(digest_ctx->sfd, NULL, 0, 0) < 0)
        return 0;

    if (recv(digest_ctx->sfd, md, len, 0) != len)
        return 0;

    return 1;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);

    if (digest_from == NULL || digest_from->init_called != 1)
        return 1;

#ifdef AFALG_ZERO_COPY
    if (pipe(digest_to->pipes) != 0)
        return 0;
#endif
    digest_to->sfd = digest_to->bfd = -1;
    if ((digest_to->bfd = accept(digest_from->bfd, NULL, 0)) != -1
        && (digest_to->sfd = accept(digest_from->sfd, NULL, 0)) != -1)
        return 1;

    SYSerr(SYS_F_ACCEPT, errno);
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

    if (digest_ctx == NULL || digest_ctx->init_called != 1)
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

        /* gather hardware driver information */
        if (afalg_alg_list_count > 0
            && (digest_driver_info[i].driver_name =
                OPENSSL_zalloc(CRYPTO_MAX_NAME)) != NULL
            && digest_driver_info[i].accelerated !=
               afalg_get_accel_info(digest_data[i].name,
                                    digest_driver_info[i].driver_name,
                                    CRYPTO_MAX_NAME)) {
            OPENSSL_strlcpy(digest_driver_info[i].driver_name,
                            "**unreliable info**", CRYPTO_MAX_NAME);
            digest_driver_info[i].accelerated = AFALG_ACCELERATION_UNKNOWN;
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

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        destroy_digest_method(digest_data[i].nid);
        OPENSSL_free(digest_driver_info[i].driver_name);
        digest_driver_info[i].driver_name = NULL;
    }
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
    char *name;
    const EVP_MD *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    EVP = EVP_get_digestbyname(name);
    if (EVP == NULL)
        fprintf(stderr, "afalg: unknown digest %s\n", name);
    else if ((i = find_digest_data_index(EVP_MD_type(EVP))) != (size_t)-1)
        digest_list[i] = 1;
    else
        fprintf(stderr, "afalg: digest %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_digest_info(void)
{
    size_t i;
    const char *evp_name;

    fprintf (stderr, "Information about digests supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        evp_name = OBJ_nid2sn(digest_data[i].nid);
        fprintf (stderr, "Digest %s, NID=%d, AF_ALG info: name=%s, ",
                 evp_name ? evp_name : "unknown", digest_data[i].nid,
                 digest_data[i].name);
        if (digest_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, "AF_ALG socket bind failed.\n");
            continue;
        }
        fprintf(stderr, " driver=%s ", digest_driver_info[i].driver_name ?
                 digest_driver_info[i].driver_name : "unknown");
        if (digest_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, "(hw accelerated)");
        else if (digest_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, "(software)");
        else
            fprintf(stderr, "(acceleration status unknown)");
        if (digest_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Digest setup failed.");
        fprintf (stderr, "\n");
    }
    fprintf(stderr, "\n");
}

/******************************************************************************
 *
 * CONTROL COMMANDS
 *
 *****/

#define AFALG_CMD_USE_SOFTDRIVERS  ENGINE_CMD_BASE
#define AFALG_CMD_CIPHERS         (ENGINE_CMD_BASE + 1)
#define AFALG_CMD_DIGESTS         (ENGINE_CMD_BASE + 2)
#define AFALG_CMD_DUMP_INFO       (ENGINE_CMD_BASE + 3)

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
     "either ALL, NONE, NO_ECB (all except ECB-mode) or a comma-separated list of ciphers to enable [default=NO_ECB]",
     ENGINE_CMD_FLAG_STRING},

   {AFALG_CMD_DIGESTS,
     "DIGESTS",
     "either ALL, NONE, or a comma-separated list of digests to enable [default=NONE]",
     ENGINE_CMD_FLAG_STRING},

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
        rebuild_known_digest_nids(e);
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

    case AFALG_CMD_DUMP_INFO:
#ifndef AFALG_NO_CRYPTOUSER
        if (afalg_alg_list_count < 0)
            fprintf (stderr, "Could not get driver info through the netlink"
                     " interface.\nIs the 'crypto_user' module loaded?\n");
#endif
        dump_cipher_info();
        dump_digest_info();
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
    destroy_all_digest_methods();

    return 1;
}


static int bind_afalg(ENGINE *e) {
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
#ifndef AFALG_NO_CRYPTOUSER
    prepare_afalg_alg_list();
#endif
    prepare_cipher_methods();
    prepare_digest_methods();
    OPENSSL_free(afalg_alg_list);
    if (afalg_alg_list_count > 0)
        afalg_alg_list_count = 0;
    return ENGINE_set_ciphers(e, afalg_ciphers) &&
        ENGINE_set_digests(e, afalg_digests);
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
