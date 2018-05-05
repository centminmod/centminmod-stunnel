stunnel install for CentOS 7 based [Centmin Mod LEMP stacks](https://centminmod.com/) only

* custom ECC 256bit ECDSA ssl certificated based stunnel installation compiled against OpenSSL 1.1.1 using GCC 7.2.1 compiler with Gold linker

```
systemctl status stunnelx
* stunnelx.service - TLS tunnel for network daemons
   Loaded: loaded (/usr/lib/systemd/system/stunnelx.service; enabled; vendor preset: disabled)
  Drop-In: /etc/systemd/system/stunnelx.service.d
           `-limit.conf
   Active: active (running) since Sat 2018-05-05 07:31:21 UTC; 9s ago
 Main PID: 8653 (stunnel)
   CGroup: /system.slice/stunnelx.service
           `-8653 /usr/local/bin/stunnel /etc/stunnel/stunnel.conf

May 05 07:31:21 host.domain.com systemd[1]: Starting TLS tunnel for network daemons...
May 05 07:31:21 host.domain.com stunnel[8652]: LOG5[ui]: stunnel 5.45 on x86_64-pc-linux-gnu platform
May 05 07:31:21 host.domain.com systemd[1]: Started TLS tunnel for network daemons.
```

```
stunnel -version
stunnel 5.45 on x86_64-pc-linux-gnu platform
Compiled/running with OpenSSL 1.1.1-pre6 (beta) 1 May 2018
Threading:PTHREAD Sockets:POLL,IPv6 TLS:ENGINE,FIPS,OCSP,PSK,SNI Auth:LIBWRAP
 
Global options:
RNDbytes               = 1024
RNDfile                = /dev/urandom
RNDoverwrite           = yes
 
Service-level options:
ciphers                = FIPS (with "fips = yes")
ciphers                = HIGH:!DH:!aNULL:!SSLv2 (with "fips = no")
curve                  = prime256v1
debug                  = daemon.notice
logId                  = sequential
options                = NO_SSLv2
options                = NO_SSLv3
sessionCacheSize       = 1000
sessionCacheTimeout    = 300 seconds
stack                  = 65536 bytes
TIMEOUTbusy            = 300 seconds
TIMEOUTclose           = 60 seconds
TIMEOUTconnect         = 10 seconds
TIMEOUTidle            = 43200 seconds
verify                 = none
```

```
/opt/stunnel-dep/bin/openssl version -a
OpenSSL 1.1.1-pre6 (beta) 1 May 2018
built on: Sat May  5 07:28:12 2018 UTC
platform: linux-x86_64
options:  bn(64,64) rc4(16x,int) des(int) idea(int) blowfish(ptr) 
compiler: ccache gcc -fPIC -pthread -m64  -Wa,--noexecstack -Wall -O3 -march=x86-64 -fuse-ld=gold -Wimplicit-fallthrough=0 -fcode-hoisting -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DNDEBUG
OPENSSLDIR: "/opt/stunnel-dep"
ENGINESDIR: "/opt/stunnel-dep/lib/engines-1.1"
Seeding source: os-specific
```

```
openssl x509 -in /etc/pki/tls/certs/stunnel.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9c:df:af:47:9d:59:bb:4c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=California, L=Los Angeles, CN=host.domain.com
        Validity
            Not Before: May  5 07:42:25 2018 GMT
            Not After : May  2 07:42:25 2028 GMT
        Subject: C=US, ST=California, L=Los Angeles, CN=host.domain.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:2b:69:42:f7:2f:4b:2f:67:cf:68:5f:0a:01:02:
                    db:0c:83:10:f4:a5:0e:ee:ef:e6:73:23:4e:d3:00:
                    ab:9a:96:2d:08:a4:53:05:91:94:e6:57:89:9f:7c:
                    8e:65:3b:47:82:93:2b:33:bc:b4:6a:0e:e0:83:78:
                    52:ba:65:ff:be
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                04:BD:64:85:FE:2B:98:3A:05:B6:CF:84:BC:69:E6:29:3E:A0:CD:BC
            X509v3 Authority Key Identifier: 
                keyid:04:BD:64:85:FE:2B:98:3A:05:B6:CF:84:BC:69:E6:29:3E:A0:CD:BC

            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:cf:c9:13:3b:a2:d9:ec:65:90:b4:a2:1e:5b:
         67:8b:ca:5c:67:12:29:26:a2:0b:9e:6f:f3:0b:23:f0:25:e4:
         91:02:21:00:88:ce:69:00:dc:41:7a:e4:8c:cb:2b:d6:f3:8d:
         01:fb:f5:1b:ea:fe:94:28:ae:d2:a5:a0:51:fa:0b:61:58:0f
```

# Redis Install On Centmin Mod LEMP stack

Default stunnel.conf sets up a Redis profile. So Redis server can be installed from Remi YUM repository using [custom Redis installer](https://github.com/centminmod/centminmod-redis) written for Centmin Mod LEMP stacks and implements the basic Redis server install steps outlined [here](https://community.centminmod.com/threads/how-to-install-redis-server-on-centmin-mod-lemp-stack.4546/).

```
mkdir -p /root/tools
cd /root/tools
git clone https://github.com/centminmod/centminmod-redis
cd centminmod-redis
if [ ! -f /usr/bin/redis-server ]; then ./redis-install.sh install; fi
service redis restart
```