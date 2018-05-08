stunnel install for CentOS 7 based [Centmin Mod LEMP stacks](https://centminmod.com/) only

* Custom ECC 256bit ECDSA ssl certificate based stunnel installation compiled with [jemalloc 5.0.1](#jemalloc) memory allocator and OpenSSL 1.1.1 using GCC 7.2.1 compiler with Gold linker
* ECDSA performance in OpenSSL 1.1.1 is [~30-40% faster](#ecdsa) than in OpenSSL 1.0.2 versions
* [TLS v1.3 ECDSA 256bit](https://github.com/centminmod/centminmod-stunnel#tls-v13---stunnel-aes-256bit---ecdsa-256bit) configuration was the fastest when stunnel compiled with [jemalloc 5.0.1](#jemalloc)
* Default stunnel config setup for Redis servers. [Redis Benchmarks - TLS v1.2 ECDSA 256bit vs RSA 2048bit](https://github.com/centminmod/centminmod-stunnel#redis-benchmarks) and [TLS v1.3 benchmarks](https://github.com/centminmod/centminmod-stunnel#tls-v13---stunnel-aes-256bit---ecdsa-256bit)

# ECDSA

From [OpenSSL 1.0.2k system](https://github.com/centminmod/centminmod-stunnel#system-openssl-102k) vs [OpenSSL 1.1.1-pre6 benchmarks](https://github.com/centminmod/centminmod-stunnel#custom-openssl-111-pre6)

|OpenSSL Version | cipher                 |     sign|    verify|    sign/s| verify/s
| --- | --- | --- | --- | --- | --- 
|OpenSSL 1.0.2k system|256 bit ecdsa (nistp256)|   0.0000s|   0.0001s|  29198.6|  11696.3
|OpenSSL 1.0.2k system|rsa 2048 bits| 0.000799s| 0.000024s|   1251.2|  42109.9
|OpenSSL 1.1.1-pre6|256 bit ecdsa (nistp256)|   0.0000s|   0.0001s|  38237.0|  12414.5
|OpenSSL 1.1.1-pre6|rsa 2048 bits| 0.000801s| 0.000024s|   1247.7|  41682.7

# stunnel-install.sh Usage

```
./stunnel-install.sh 

Usage:
./stunnel-install.sh {install|update|update-certs|reinstall|check|openssl
```

# custom installed stunnel info

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
stunnel -options
stunnel 5.45 on x86_64-pc-linux-gnu platform
Compiled/running with OpenSSL 1.1.1-pre6 (beta) 1 May 2018
Threading:PTHREAD Sockets:POLL,IPv6 TLS:ENGINE,FIPS,OCSP,PSK,SNI Auth:LIBWRAP
 
Supported TLS options:
options = MICROSOFT_SESS_ID_BUG
options = NETSCAPE_CHALLENGE_BUG
options = LEGACY_SERVER_CONNECT
options = NETSCAPE_REUSE_CIPHER_CHANGE_BUG
options = TLSEXT_PADDING
options = MICROSOFT_BIG_SSLV3_BUFFER
options = SAFARI_ECDHE_ECDSA_BUG
options = SSLEAY_080_CLIENT_DH_BUG
options = TLS_D5_BUG
options = TLS_BLOCK_PADDING_BUG
options = MSIE_SSLV2_RSA_PADDING
options = SSLREF2_REUSE_CERT_TYPE_BUG
options = DONT_INSERT_EMPTY_FRAGMENTS
options = ALL
options = NO_QUERY_MTU
options = COOKIE_EXCHANGE
options = NO_TICKET
options = CISCO_ANYCONNECT
options = NO_SESSION_RESUMPTION_ON_RENEGOTIATION
options = NO_COMPRESSION
options = ALLOW_UNSAFE_LEGACY_RENEGOTIATION
options = SINGLE_ECDH_USE
options = SINGLE_DH_USE
options = EPHEMERAL_RSA
options = CIPHER_SERVER_PREFERENCE
options = TLS_ROLLBACK_BUG
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_TLSv1_3
options = PKCS1_CHECK_1
options = PKCS1_CHECK_2
options = NETSCAPE_CA_DN_BUG
options = NETSCAPE_DEMO_CIPHER_CHANGE_BUG
options = CRYPTOPRO_TLSEXT_BUG
options = NO_DTLSv1
options = NO_DTLSv1_2
options = NO_SSL_MASK
options = NO_DTLS_MASK
options = NO_ENCRYPT_THEN_MAC
options = ALLOW_NO_DHE_KEX
options = ENABLE_MIDDLEBOX_COMPAT
options = NO_RENEGOTIATION
options = PRIORITIZE_CHACHA
```

```
/opt/stunnel-dep/bin/openssl version -a
OpenSSL 1.1.1-pre6 (beta) 1 May 2018
built on: Mon May  7 08:48:34 2018 UTC
platform: linux-x86_64
options:  bn(64,64) rc4(16x,int) des(int) idea(int) blowfish(ptr) 
compiler: ccache gcc -fPIC -pthread -m64  -Wa,--noexecstack -Wall -O3 -march=x86-64 -fuse-ld=gold -Wimplicit-fallthrough=0 -fcode-hoisting -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DZLIB -DNDEBUG
OPENSSLDIR: "/opt/stunnel-dep"
ENGINESDIR: "/opt/stunnel-dep/lib64/engines-1.1"
Seeding source: os-specific
```

```
openssl x509 -in /etc/stunnel/stunnel.pem -text -noout
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

Redis server on local port 6379

```
redis-cli -h 127.0.0.1 -p 6379 info server
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:8e246a05989e6d22
redis_mode:standalone
os:Linux 2.6.32-042stab128.2 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:4.8.5
process_id:402
run_id:16e31dd41471b36ed4acd81f266f9c25b067690a
tcp_port:6379
uptime_in_seconds:40771
uptime_in_days:0
hz:10
lru_clock:15635653
executable:/usr/bin/redis-server
config_file:/etc/redis.conf
```

Redis server connection through stunnel configured local port 8379

```
redis-cli -h 127.0.0.1 -p 8379 info server                                                                    
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:8e246a05989e6d22
redis_mode:standalone
os:Linux 2.6.32-042stab128.2 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:4.8.5
process_id:402
run_id:16e31dd41471b36ed4acd81f266f9c25b067690a
tcp_port:6379
uptime_in_seconds:40820
uptime_in_days:0
hz:10
lru_clock:15635702
executable:/usr/bin/redis-server
config_file:/etc/redis.conf
```

# Redis benchmarks

Average of 3 `redis-benchmark` runs

|Config: OpenSSL 1.1.1-pre6|Protocol|Cert Type|Cipher|Redis SET|Redis GET
|---|---|---|---|---|---
|Redis direct 6379|none|none|none|680141|818266
|Redis Stunnel|TLSv1.2|ECDSA 256bit|ECDHE-ECDSA-AES256-GCM-SHA384|149421|154861
|Redis Stunnel|TLSv1.2|RSA 2048bit|ECDHE-RSA-AES256-GCM-SHA384|139251|154051
|Redis Stunnel|TLSv1.2|ECDSA 256bit|ECDHE-ECDSA-AES128-GCM-SHA256|145696|178730
|Redis Stunnel|TLSv1.2|RSA 2048bit|ECDHE-RSA-AES128-GCM-SHA256|139941|154908
|Redis Stunnel|TLSv1.3|ECDSA 256bit|TLS_AES_256_GCM_SHA384|172316|193784
|Redis Stunnel SO_REUSEADDR=yes|TLSv1.3|ECDSA 256bit|TLS_AES_256_GCM_SHA384|184652|188590
|Redis Stunnel SO_REUSEADDR=yes + jemalloc 5.0.1|TLSv1.3|ECDSA 256bit|TLS_AES_256_GCM_SHA384|208696|214477

Redis direct port 6379

```
redis-benchmark -h 127.0.0.1 -p 6379 -n 1000000 -t set,get -P 32 -q -c 200
```

```
redis-benchmark -h 127.0.0.1 -p 6379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 695410.31 requests per second
GET: 833333.31 requests per second

redis-benchmark -h 127.0.0.1 -p 6379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 669792.38 requests per second
GET: 793650.81 requests per second

redis-benchmark -h 127.0.0.1 -p 6379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 675219.50 requests per second
GET: 827814.62 requests per second
```

## TLS v1.2 - Stunnel AES 256bit - ECDSA 256bit vs RSA 2048bit

Redis via stunnel port 8379 with ECC 256bit ECDSA SSL certs and `TLS 1.2` - `AES 256bit`

```
echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/stunnel/stunnel.pem 2>&1 | grep -A2 'SSL-Session:'
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES256-GCM-SHA384
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 137646.25 requests per second
GET: 136295.48 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 128600.82 requests per second
GET: 171791.78 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 182016.75 requests per second
GET: 156494.53 requests per second
```

Redis via stunnel port 8379 with RSA 2048bit Standard SSL certs and `TLS 1.2` - `AES 256bit`

```
echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/stunnel/stunnel.pem 2>&1 | grep -A2 'SSL-Session:'
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 117980.18 requests per second
GET: 129684.87 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 129416.33 requests per second
GET: 170823.36 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 170357.75 requests per second
GET: 161655.36 requests per second
```

## TLS v1.2 - Stunnel AES 128bit - ECDSA 256bit vs RSA 2048bit

Redis via stunnel port 8379 with ECC 256bit ECDSA SSL certs and `TLS 1.2` - `AES 128bit`

```
echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/stunnel/stunnel.pem 2>&1 | grep -A2 'SSL-Session:'
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 138850.31 requests per second
GET: 176928.52 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 144864.55 requests per second
GET: 186011.91 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 153374.23 requests per second
GET: 173250.17 requests per second
```

Redis via stunnel port 8379 with RSA 2048bit Standard SSL certs and `TLS 1.2` - `AES 128bit`

```
echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/stunnel/stunnel.pem 2>&1 | grep -A2 'SSL-Session:'
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 117109.73 requests per second
GET: 148853.83 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 147601.47 requests per second
GET: 154607.30 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 155110.91 requests per second
GET: 161264.31 requests per second
```

## TLS v1.3 - Stunnel AES 256bit - ECDSA 256bit

Redis via stunnel port 8379 with ECC 256bit ECDSA SSL certs and `TLS 1.3` - `AES 256bit`

```
/opt/stunnel-dep/bin/openssl ciphers -V '1.3'     
    0x13,0x02 - TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD
    0x13,0x03 - TLS_CHACHA20_POLY1305_SHA256 TLSv1.3 Kx=any      Au=any  Enc=CHACHA20/POLY1305(256) Mac=AEAD
    0x13,0x01 - TLS_AES_128_GCM_SHA256  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD
```

```
awk '/ciphersuite/ {print $4,$5,$6,$7}' /var/log/stunnel.log | uniq
TLSv1.3 ciphersuite: TLS_AES_256_GCM_SHA384 (256-bit
```

```
echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/stunnel/stunnel.pem 2>&1 | grep -A2 'SSL-Session:'
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 150784.08 requests per second
GET: 186811.12 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 174520.06 requests per second
GET: 204498.98 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 191644.31 requests per second
GET: 190041.81 requests per second
```

With `SO_REUSEADDR=yes` Redis via stunnel port 8379 with ECC 256bit ECDSA SSL certs and `TLS 1.3` - `AES 256bit`

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200        
SET: 153633.44 requests per second
GET: 193311.44 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 200561.56 requests per second
GET: 181290.80 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 199760.28 requests per second
GET: 191168.03 requests per second
```

### jemalloc

With `jemalloc 5.0.1` memory allocator + `SO_REUSEADDR=yes` Redis via stunnel port 8379 with ECC 256bit ECDSA SSL certs and `TLS 1.3` - `AES 256bit`

```
lsof | grep stunnel | grep jemalloc
stunnel   30512         stunnel  mem       REG         182,160625   3429720  2912291 /opt/stunnel-dep/lib/libjemalloc.so.2
stunnel   30512 30513   stunnel  mem       REG         182,160625   3429720  2912291 /opt/stunnel-dep/lib/libjemalloc.so.2
```

```
redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200                                                                            
SET: 200481.16 requests per second
GET: 214362.28 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 217013.89 requests per second
GET: 205254.50 requests per second

redis-benchmark -h 127.0.0.1 -p 8379 -n 1000000 -t set,get -P 32 -q -c 200
SET: 208594.06 requests per second
GET: 223813.80 requests per second
```

Centmin Mod LEMP stack currently uses `jemalloc` for MariaDB 10.0/10.1 MySQL, Redis server, custom built Nginx 1.13 or 1.14 binaries. So custom built stunnel is at home with `jemalloc` - though a new version 5.0.1 instead of system `jemalloc 3.6.0` version. Using `jemalloc` instead of `glibc` malloc for Nginx also lessens the negative performance impact of the [latest Linux Kernel KPTI + Retpoline Meltdown and Spectre vulnerability patches](https://community.centminmod.com/threads/linux-kernel-security-updates-for-spectre-meltdown-vulnerabilities.13648/) dropping the [KPTI performance overhead in Nginx from around 26% to 5.5%](https://community.centminmod.com/threads/nginx-benchmarks-after-centos-linux-kernel-kpti-meltdown-spectre-fixes.13694/).

This server's OpenVZ 2.6.32 Kernel has KPTI patches enabled from `pti` in cpu flags list. So wonder if compiling stunnel with `jemalloc` boosted performance due to KPTI Kernel patches overhead ?

```
uname -r
2.6.32-042stab128.2
```

```
grep 'pti ' /proc/cpuinfo | uniq
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon pebs bts rep_good xtopology nonstop_tsc aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm ida arat epb pln pts dtherm pti retpoline tpr_shadow vnmi flexpriority ept vpid xsaveopt
```

```
lsof | grep jemalloc
mysqld      662           mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   715     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   796     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   813     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   814     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   815     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   816     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   817     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   818     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   819     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   824     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   825     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   826     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   827     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   828     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   829     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   830     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   831     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   833     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   834     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   838     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662   842     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
mysqld      662  9832     mysql  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
redis-ser  2554           redis  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
redis-ser  2554  2555     redis  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
redis-ser  2554  2556     redis  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
redis-ser  2554  2557     redis  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
nginx     24823            root  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
nginx     24824           nginx  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
nginx     24826           nginx  mem       REG         182,160625    212096   2240459 /usr/lib64/libjemalloc.so.1
stunnel   31347         stunnel  mem       REG         182,160625   3635232   2904765 /opt/stunnel-dep/lib/libjemalloc.so.2
stunnel   31347 31348   stunnel  mem       REG         182,160625   3635232   2904765 /opt/stunnel-dep/lib/libjemalloc.so.2`
```

`jemalloc 5.0.1` stats

```
jemalloc5-stats                                 
___ Begin jemalloc statistics ___
Version: 5.0.1-0-g1
Assertions disabled
config.malloc_conf: ""
Run-time option settings:
  opt.abort: false
  opt.abort_conf: false
  opt.retain: true
  opt.dss: "secondary"
  opt.narenas: 8
  opt.percpu_arena: "disabled"
  opt.background_thread: false (background_thread: false)
  opt.dirty_decay_ms: 10000 (arenas.dirty_decay_ms: 10000)
  opt.muzzy_decay_ms: 10000 (arenas.muzzy_decay_ms: 10000)
  opt.junk: "false"
  opt.zero: false
  opt.tcache: true
  opt.lg_tcache_max: 15
  opt.stats_print: false
Arenas: 8
Quantum size: 16
Page size: 4096
Maximum thread-cached size class: 32768
Allocated: 55261928, active: 58871808, metadata: 2495768, resident: 61345792, mapped: 65163264, retained: 7188480
                           n_lock_ops       n_waiting      n_spin_acq  n_owner_switch   total_wait_ns     max_wait_ns  max_n_thds
background_thread:                  4               0               0               1               0               0           0
ctl:                                2               0               0               1               0               0           0
prof:                               0               0               0               0               0               0           0

arenas[0]:
assigned threads: 1
uptime: 999989
dss allocation precedence: secondary
decaying:  time       npages       sweeps     madvises       purged
   dirty: 10000            0            0            0            0
   muzzy: 10000            0            0            0            0
                            allocated      nmalloc      ndalloc    nrequests
small:                        1682152          851            0           61
large:                       53579776          857            0          857
total:                       55261928         1708            0          918
active:                      58871808
mapped:                      65163264
retained:                     7188480
base:                         2467088
internal:                       28680
tcache:                        559464
resident:                    61345792
                           n_lock_ops       n_waiting      n_spin_acq  n_owner_switch   total_wait_ns     max_wait_ns  max_n_thds
large:                              2               0               0               1               0               0           0
extent_avail:                     981               0               0               3               0               0           0
extents_dirty:                    972               0               0               3               0               0           0
extents_muzzy:                    972               0               0               3               0               0           0
extents_retained:                1940               0               0               3               0               0           0
decay_dirty:                        2               0               0               1               0               0           0
decay_muzzy:                        2               0               0               1               0               0           0
base:                            1000               0               0               3               0               0           0
tcache_list:                        3               0               0               1               0               0           0
bins:           size ind    allocated      nmalloc      ndalloc    nrequests      curregs     curslabs regs pgs  util       nfills     nflushes     newslabs      reslabs   n_lock_ops    n_waiting   n_spin_acq  total_wait_ns  max_wait_ns
                   8   0          808          101            0            1          101            1  512   1 0.197            1            0            1            0            5            0            0              0            0
                     ---
                  32   2         3200          100            0            0          100            1  128   1 0.781            1            0            1            0            4            0            0              0            0
                     ---
                 112   7        11200          100            0            0          100            1  256   7 0.390            1            0            1            0            4            0            0              0            0
                     ---
                 224  11        22400          100            0            0          100            1  128   7 0.781            1            0            1            0            4            0            0              0            0
                     ---
                 320  13        20480           64            0            0           64            1   64   5 1                1            0            1            0            4            0            0              0            0
                     ---
                 448  15        28672           64            0            0           64            1   64   7 1                1            0            1            0            4            0            0              0            0
                 512  16         5120           10            0            0           10            2    8   1 0.625            1            0            2            0            5            0            0              0            0
                 640  17        20480           32            0            0           32            1   32   5 1                1            0            1            0            4            0            0              0            0
                 768  18        12288           16            0            0           16            1   16   3 1                1            0            1            0            4            0            0              0            0
                 896  19        28672           32            0            0           32            1   32   7 1                1            0            1            0            4            0            0              0            0
                1024  20        10240           10            0            0           10            3    4   1 0.833            1            0            3            0            6            0            0              0            0
                1280  21        20480           16            0            0           16            1   16   5 1                1            0            1            0            4            0            0              0            0
                1536  22        15360           10            0            0           10            2    8   3 0.625            1            0            2            0            5            0            0              0            0
                1792  23        28672           16            0            0           16            1   16   7 1                1            0            1            0            4            0            0              0            0
                2048  24        20480           10            0            0           10            5    2   1 1                1            0            5            0            8            0            0              0            0
                2560  25        25600           10            0            0           10            2    8   5 0.625            1            0            2            0            5            0            0              0            0
                3072  26        30720           10            0            0           10            3    4   3 0.833            1            0            3            0            6            0            0              0            0
                3584  27        35840           10            0            0           10            2    8   7 0.625            1            0            2            0            5            0            0              0            0
                4096  28        40960           10            0            0           10           10    1   1 1                1            0           10            0           13            0            0              0            0
                5120  29       102400           20            0           10           20            5    4   5 1                2            0            5            0            9            0            0              0            0
                6144  30        61440           10            0            0           10            5    2   3 1                1            0            5            0            8            0            0              0            0
                7168  31        71680           10            0            0           10            3    4   7 0.833            1            0            3            0            6            0            0              0            0
                8192  32        81920           10            0            0           10           10    1   2 1                1            0           10            0           13            0            0              0            0
               10240  33       307200           30            0           20           30           15    2   5 1                3            0           15            0           20            0            0              0            0
               12288  34       245760           20            0           10           20           20    1   3 1                2            0           20            0           24            0            0              0            0
               14336  35       430080           30            0           20           30           15    2   7 1                3            0           15            0           20            0            0              0            0
large:          size ind    allocated      nmalloc      ndalloc    nrequests  curlextents
               16384  36       327680           20            0           20           20
               20480  37       839680           41            0           41           41
               24576  38      1007616           41            0           41           41
               28672  39      1204224           42            0           42           42
               32768  40      1343488           41            0           41           41
               40960  41      3358720           82            0           82           82
               49152  42      4030464           82            0           82           82
               57344  43      4702208           82            0           82           82
               65536  44      5373952           82            0           82           82
               81920  45     13434880          164            0          164          164
               98304  46     16121856          164            0          164          164
              114688  47      1835008           16            0           16           16
                     ---
--- End jemalloc statistics ---
```

## Redis Server Background Specs

On 2 core Intel Xeon E5-2670v1 @2.60Ghz OpenVZ VPS server

```
dd if=/dev/zero of=/dev/null 
9684753+0 records in
9684753+0 records out
4958593536 bytes (5.0 GB) copied, 10.6449 s, 466 MB/s
```

```
dd if=/dev/random of=/dev/null  
0+196607 records in
29948+0 records out
15333376 bytes (15 MB) copied, 10.0214 s, 1.5 MB/s
```
```
dd if=/dev/urandom of=/dev/null 
105186+0 records in
105185+0 records out
53854720 bytes (54 MB) copied, 9.95861 s, 5.4 MB/s
```

### System OpenSSL 1.0.2k

```
CPUS=2
OPENSSL_BINPATH='/usr/bin/openssl'
$OPENSSL_BINPATH speed -multi ${CPUS} rsa4096 rsa2048 ecdsap256 sha256 sha1 md5 rc4 aes-256-cbc aes-128-cbc
$OPENSSL_BINPATH speed -evp aes256 -multi ${CPUS}
$OPENSSL_BINPATH speed -evp aes128 -multi ${CPUS}

OpenSSL 1.0.2k-fips  26 Jan 2017
built on: reproducible build, date unspecified
options:bn(64,64) md2(int) rc4(16x,int) des(idx,cisc,16,int) aes(partial) idea(int) blowfish(idx) 
compiler: gcc -I. -I.. -I../include  -fPIC -DOPENSSL_PIC -DZLIB -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DKRB5_MIT -m64 -DL_ENDIAN -Wall -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -Wa,--noexecstack -DPURIFY -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM
md5              78286.02k   236562.15k   539289.34k   805205.33k   935010.30k
sha1             95498.75k   275328.62k   613020.16k   873856.34k   988973.74k
rc4             614633.93k   979997.40k  1131005.44k  1160783.53k  1204794.71k
aes-128 cbc     157016.10k   167505.05k   169763.84k   171316.22k   172660.05k
aes-256 cbc     114081.28k   120184.87k   121717.85k   121146.37k   121913.34k
sha256           86382.77k   192901.87k   334106.71k   412383.57k   436051.97k
                  sign    verify    sign/s verify/s
rsa 2048 bits 0.000799s 0.000024s   1251.2  42109.9
rsa 4096 bits 0.005704s 0.000089s    175.3  11236.3
                              sign    verify    sign/s verify/s
 256 bit ecdsa (nistp256)   0.0000s   0.0001s  29198.6  11696.3

OpenSSL 1.0.2k-fips  26 Jan 2017
built on: reproducible build, date unspecified
options:bn(64,64) md2(int) rc4(16x,int) des(idx,cisc,16,int) aes(partial) idea(int) blowfish(idx) 
compiler: gcc -I. -I.. -I../include  -fPIC -DOPENSSL_PIC -DZLIB -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DKRB5_MIT -m64 -DL_ENDIAN -Wall -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -Wa,--noexecstack -DPURIFY -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM
evp             685059.22k   716561.00k   725262.59k   727466.67k   724923.73k

OpenSSL 1.0.2k-fips  26 Jan 2017
built on: reproducible build, date unspecified
options:bn(64,64) md2(int) rc4(16x,int) des(idx,cisc,16,int) aes(partial) idea(int) blowfish(idx) 
compiler: gcc -I. -I.. -I../include  -fPIC -DOPENSSL_PIC -DZLIB -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DKRB5_MIT -m64 -DL_ENDIAN -Wall -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -Wa,--noexecstack -DPURIFY -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM
evp             930255.34k   995847.81k  1013017.09k  1016555.86k  1018219.18k
```

### Custom OpenSSL 1.1.1-pre6

```
CPUS=2
OPENSSL_BINPATH='/opt/stunnel-dep/bin/openssl'
$OPENSSL_BINPATH speed -multi ${CPUS} rsa4096 rsa2048 ecdsap256 sha256 sha1 md5 rc4 aes-256-cbc aes-128-cbc
$OPENSSL_BINPATH speed -evp aes256 -multi ${CPUS}
$OPENSSL_BINPATH speed -evp aes128 -multi ${CPUS}

OpenSSL 1.1.1-pre6 (beta) 1 May 2018
built on: Sun May  6 09:23:43 2018 UTC
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr) 
compiler: ccache gcc -fPIC -pthread -m64  -Wa,--noexecstack -Wall -O3 -march=x86-64 -fuse-ld=gold -Wimplicit-fallthrough=0 -fcode-hoisting -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DNDEBUG
md5             166551.94k   392143.59k   696030.04k   863324.84k   915111.94k   940889.43k
sha1            157937.08k   387046.93k   718987.01k   934882.30k  1022451.71k  1027407.87k
rc4             605383.53k   970227.82k  1136071.59k  1177563.82k  1201012.74k  1198746.28k
aes-128 cbc     156092.92k   169357.29k   170210.73k   173428.39k   174148.27k   174314.84k
aes-256 cbc     115043.86k   121271.59k   122045.10k   121122.82k   122579.63k   122530.47k
sha256           90741.52k   196594.58k   339540.05k   410104.49k   440257.19k   438392.15k
                  sign    verify    sign/s verify/s
rsa 2048 bits 0.000801s 0.000024s   1247.7  41682.7
rsa 4096 bits 0.005659s 0.000088s    176.7  11416.6
                              sign    verify    sign/s verify/s
 256 bit ecdsa (nistp256)   0.0000s   0.0001s  38237.0  12414.5

OpenSSL 1.1.1-pre6 (beta) 1 May 2018
built on: Sun May  6 09:23:43 2018 UTC
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr) 
compiler: ccache gcc -fPIC -pthread -m64  -Wa,--noexecstack -Wall -O3 -march=x86-64 -fuse-ld=gold -Wimplicit-fallthrough=0 -fcode-hoisting -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DNDEBUG
evp             617543.15k   705934.66k   723616.51k   723812.01k   726867.97k   725510.83k

OpenSSL 1.1.1-pre6 (beta) 1 May 2018
built on: Sun May  6 09:23:43 2018 UTC
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr) 
compiler: ccache gcc -fPIC -pthread -m64  -Wa,--noexecstack -Wall -O3 -march=x86-64 -fuse-ld=gold -Wimplicit-fallthrough=0 -fcode-hoisting -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DNDEBUG
evp             860017.24k   981170.22k  1011554.56k  1018749.61k  1017612.97k  1012465.66k
```

### CPU Specs

```
cat /proc/cpuinfo
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 45
model name      : Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz
stepping        : 6
microcode       : 1561
cpu MHz         : 2599.889
cache size      : 20480 KB
physical id     : 0
siblings        : 16
core id         : 0
cpu cores       : 8
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon pebs bts rep_good xtopology nonstop_tsc aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm ida arat epb pln pts dtherm pti retpoline tpr_shadow vnmi flexpriority ept vpid xsaveopt
bogomips        : 5199.77
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:

processor       : 1
vendor_id       : GenuineIntel
cpu family      : 6
model           : 45
model name      : Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz
stepping        : 6
microcode       : 1561
cpu MHz         : 2599.889
cache size      : 20480 KB
physical id     : 0
siblings        : 16
core id         : 1
cpu cores       : 8
apicid          : 2
initial apicid  : 2
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon pebs bts rep_good xtopology nonstop_tsc aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm ida arat epb pln pts dtherm pti retpoline tpr_shadow vnmi flexpriority ept vpid xsaveopt
bogomips        : 5199.77
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:
```