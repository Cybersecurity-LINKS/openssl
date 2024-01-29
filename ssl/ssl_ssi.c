#include <openssl/ssl.h>
#include "ssl_local.h"

#ifndef OPENSSL_NO_VCAUTHTLS
/* Default did methods schemes */
static const uint16_t didmethods[] = {
    TLSEXT_DIDMETH_btcr,
    TLSEXT_DIDMETH_ethr,
    TLSEXT_DIDMETH_iota,
};
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int SSL_CTX_use_VC(SSL_CTX *ctx, EVP_PKEY *vc) 
{   
    ctx->vc->vc = vc;
    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int SSL_CTX_use_DID(SSL_CTX *ctx, EVP_PKEY *did)
{
    ctx->vc->did = did;
    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
VC_PKEY *ssl_vc_new(size_t ssl_pkey_num) {

    VC_PKEY *ret = NULL;

    /* Should never happen */
    /* if (!ossl_assert(ssl_pkey_num >= SSL_PKEY_NUM))
        return NULL; */

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;

    return ret;    
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
VC_PKEY *ssl_vc_dup(VC_PKEY *vc)
{
    VC_PKEY *ret = OPENSSL_zalloc(sizeof(*ret));
    /* size_t i; */

    if (ret == NULL)
        return NULL;

    if(vc->did != NULL) {
        ret->did = vc->did;
        EVP_PKEY_up_ref(vc->did);
    }

    if(vc->vc != NULL) {
        ret->vc = vc->vc;
        EVP_PKEY_up_ref(vc->vc);
    }

    return ret;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
/* Returns true if VC and DID are present */
int ssl_has_vc(const SSL_CONNECTION *s)
{
    if (ssl_has_cert_type(s, TLSEXT_cert_type_vc))
        return s->vc->vc != NULL && s->vc->did != NULL;

    return 0;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int ssl_setup_didmethods(SSL_CTX *ctx) {

    size_t i, didmethods_len;
    uint16_t *didmethods_list = NULL;
    int ret = 0;

    if (ctx == NULL)
        goto err; 

    didmethods_len = OSSL_NELEM(didmethods);

    didmethods_list = OPENSSL_malloc(sizeof(uint16_t) * didmethods_len);
    if (didmethods_list == NULL)
        goto err;

    for (i = 0; i < didmethods_len; i ++) {
        didmethods_list[i] = didmethods[i];
    }

    ctx->ext.didmethods = didmethods_list;
    ctx->ext.didmethods_len = didmethods_len;
    didmethods_list = NULL;

    ret = 1;
err:
    OPENSSL_free(didmethods_list);
    return ret;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int set_server_didmethods(SSL_CONNECTION *s) {

    /* The server checks if the client sent the did_methods extension and set the 
    did_methods they have in common */

    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int process_didmethods(SSL_CONNECTION *s) {

    return 1;
}
#endif