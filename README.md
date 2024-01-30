# Purpose  

This is a fork of OpenSSL to enable TLS 1.3 authentication through the use of Verifiable Credentials. The original OpenSSL `README` can be found at [OpenSSL](./README-OPENSSL.md)

# Architecture

This version of OpenSSL leverages the [ssi-provider](https://github.com/Cybersecurity-LINKS/openssl-ssi-provider) to perform operations that involve the usage of Verifiable Credentials.

# Build

We have added the `vcauthtls` option in the `Configure` file to enable VC authentication in the TLS 1.3 handshake. The option is disabled by default, so when you run the `Configure` file you need to add the option `enable-vcauthtls`.

# Usage

You can create your Self-Sovereign Identity through the `genpkey` application treating the DID Document as the public part and the VC as the private part of an asymmetric keypair.

    openssl genpkey -algorithm VC -out did-document.pem -outpubkey vc.pem -provider default -provider ssi

To perform a TLS 1.3 handshake with VC authentication you can run locally `s_server` and `s_client` applications with the following options:

    openssl s_server -accept 44330 -www -cert server-vc.pem -key server-did-document.pem -verify 1 -enable_client_rpk -enable_server_rpk -tls1_3 -provider default -provider ssi

    openssl s_client -connect localhost:44330 -cert client-vc.pem -key client-did-document.pem -enable_client_rpk -enable_server_rpk -tls1_3 -provider default -provider ssi 
