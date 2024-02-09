/*
 * Copyright 2024 Fondazione LINKS.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

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
int SSL_CTX_use_VC(EVP_PKEY *vc, SSL_CTX *ctx) 
{   
    size_t i;

    if (ssl_cert_lookup_by_pkey(vc, &i, ctx) == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        return 0;
    }

    ctx->ssi->pkeys[i].vc = vc;
    ctx->ssi->key = &ctx->ssi->pkeys[i];
    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int SSL_CTX_use_DID(EVP_PKEY *did, SSL_CTX *ctx)
{   
    size_t i;

     if (ssl_cert_lookup_by_pkey(did, &i, ctx) == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        return 0;
    }

    ctx->ssi->pkeys[i].did = did;
    ctx->ssi->key = &ctx->ssi->pkeys[i];
    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
EVP_PKEY *SSL_get0_peer_vc(const SSL *s) {

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    if (sc == NULL || sc->session == NULL)
        return NULL;
    return sc->session->peer_vc;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
struct ssi_st *ssl_ssi_new(size_t ssl_pkey_num) {

    SSI *ret = NULL;

    /* Should never happen */
    if (!ossl_assert(ssl_pkey_num >= SSL_PKEY_NUM))
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;

    ret->ssl_pkey_num = ssl_pkey_num;
    ret->pkeys = OPENSSL_zalloc(ret->ssl_pkey_num * sizeof(SSI_PKEY));
    if (ret->pkeys == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    ret->key = &(ret->pkeys[SSL_PKEY_RSA]);
    /* ret->sec_cb = ssl_security_default_callback;
    ret->sec_level = OPENSSL_TLS_SECURITY_LEVEL;
    ret->sec_ex = NULL; */
    if (!CRYPTO_NEW_REF(&ret->references, 1)) {
        OPENSSL_free(ret->pkeys);
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;    
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
struct ssi_st *ssl_ssi_dup(SSI *ssi)
{
    SSI *ret = OPENSSL_zalloc(sizeof(*ret));
    size_t i;

    if (ret == NULL)
        return NULL;

    ret->ssl_pkey_num = ssi->ssl_pkey_num;
    ret->pkeys = OPENSSL_zalloc(ret->ssl_pkey_num * sizeof(SSI_PKEY));
    if (ret->pkeys == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    ret->key = &ret->pkeys[ssi->key - ssi->pkeys];
    if (!CRYPTO_NEW_REF(&ret->references, 1)) {
        OPENSSL_free(ret->pkeys);
        OPENSSL_free(ret);
        return NULL;
    }

    for (i = 0; i < ret->ssl_pkey_num; i++) {
        SSI_PKEY *cpk = ssi->pkeys + i;
        SSI_PKEY *rpk = ret->pkeys + i;

        if(cpk->did != NULL) {
            rpk->did = cpk->did;
            EVP_PKEY_up_ref(cpk->did);
        }

        if(cpk->vc != NULL) {
            rpk->vc = cpk->vc;
            EVP_PKEY_up_ref(cpk->vc);
        }   
    }

    return ret;
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
static int tls13_shared_didmethods(SSL_CONNECTION *s,
                                   const uint16_t **shdidmethods,
                                   const uint16_t *pref, size_t preflen,
                                   const uint16_t *allow, size_t allowlen) {
    const uint16_t *ptmp, *atmp;
    size_t i, j, nmatch = 0;

    for(i = 0, ptmp = pref; i < preflen; i++, ptmp++) {
        for (j = 0, atmp = allow; j < allowlen; j++, atmp++) {
            if (*ptmp == *atmp) {
                nmatch++;
                if (shdidmethods)
                    *shdidmethods++ = ptmp;
                break;
            }
        }        
    }
    return nmatch;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
static int tls13_check_shared_didmethods(SSL_CONNECTION *s,
                                   const uint16_t *pref, size_t preflen,
                                   const uint16_t *allow, size_t allowlen) {
    const uint16_t *ptmp, *atmp;
    size_t i, j;

    for(i = 0, ptmp = pref; i < preflen; i++, ptmp++) {
            for (j = 0, atmp = allow; j < allowlen; j++, atmp++) {
                if (*ptmp == *atmp)
                    break;
            }
            if(j == allowlen)
                return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
static int tls13_set_shared_didmethods(SSL_CONNECTION *s)
{
    const uint16_t *pref, *allow;
    const uint16_t **shdidmethods = NULL;
    size_t preflen, allowlen;
    size_t nmatch;

    OPENSSL_free(s->shared_didmethods);
    s->shared_didmethods = NULL;
    s->shared_didmethodslen = 0;

    pref = s->ext.peer_didmethods;
    preflen = s->ext.peer_didmethods_len;
    allow = s->ext.didmethods;
    allowlen = s->ext.didmethods_len;

    /* On client side check that each did method sent by the server belong to the client list */
    if(!s->server)
        if(!tls13_check_shared_didmethods(s, pref, preflen, allow, allowlen))
            return 0;

    nmatch = tls13_shared_didmethods(s, NULL, pref, preflen, allow, allowlen);
    if (nmatch) {
        if ((shdidmethods = OPENSSL_malloc(nmatch * sizeof(*shdidmethods))) == NULL)
            return 0;
        nmatch = tls13_shared_didmethods(s, shdidmethods, pref, preflen, allow, allowlen);
    } else {
        shdidmethods = NULL;
        return 0; /*  Maybe should be omitted */
    }
    s->shared_didmethods = shdidmethods;
    s->shared_didmethodslen = nmatch;
    return 1;
}   
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int set_server_didmethods(SSL_CONNECTION *s) {


    if(s->ext.client_cert_type != TLSEXT_cert_type_vc || !send_certificate_request(s))
        return 1;

    /* The server must have a list of did methods to send */
    if(send_certificate_request(s) && s->ext.didmethods == NULL) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
             SSL_R_TLSV13_ALERT_MISSING_EXTENSION);
        return 0;
    }
    /* Some day MUST also be checked that the server's DID belongs to the list sent by the client */

    /* If they both authenticate with VC the server must send a list of 
    did methods the two have in common. */
    if(s->ext.server_cert_type == TLSEXT_cert_type_vc)
            return tls13_set_shared_didmethods(s);

    /* The server will send the full list of did methods */
    return 1;
}
#endif

#ifndef OPENSSL_NO_VCAUTHTLS
int process_didmethods(SSL_CONNECTION *s) {

    /*  If client certificate type is set to VC the list sent by the server can't be empty */
    if(s->ext.peer_didmethods == NULL) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
             SSL_R_TLSV13_ALERT_MISSING_EXTENSION /* This should be changed to something more appropriate */);
        return 0;
    }

    /* If the client sent the did methods extension checks that the list sent by the server 
    is a subset of its list */
    if(s->ext.didmethods_sent) {
        if(!tls13_set_shared_didmethods(s)) {
            SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
             SSL_R_TLSV13_ALERT_MISSING_EXTENSION /* This should be changed to something more appropriate */);
            return 0;
        }
    }

    /* Otherwise accepts the whole list sent by the server */
    /* Some day MUST also be checked that the client's DID belongs to the list sent by the server */

    return 1;
}
#endif