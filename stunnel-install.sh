#!/bin/bash
#########################################################
# stunnel installed as service name = stunnelx so as to
# not conflict with system yum installed stunnel versions
#
# custom stunnel install for centmin mod lemp stacks with
# performance in mind compiled against openssl 1.1.1 with
# ecdsa instead of rsa based ssl certificates for better
# scalability and performance out of the box
#
# stunnel & openssl 1.1.1 are compiled against GCC 7.2.1
# compiler with Gold linker if detected on the server
#
# written by George Liu (eva2000) https://centminmod.com
#########################################################
# variables
#############
VER='0.8'
DT=$(date +"%d%m%y-%H%M%S")
DIR_TMP='/svr-setup'

STUNNEL_VERSION='5.45b8'
# whether stunnel.conf redis is setup as client or server
# default is to setup as redis server stunnel server end
STUNNEL_CLIENT='n'
# ecdsa or rsa
STUNNEL_CERTTYPE='ecdsa'
# stunnel ssl cert expiry date default in days
STUNNEL_CERTEXPIRY='3650'
# stunnel max open file descriptor limit
STUNNEL_FD='1048576'
# where openssl 1.1.1 libraries get installed
STUNNEL_LIBDIR='/opt/stunnel-dep'
# openssl 1.1.1 version
STUNNEL_OPENSSLVER='1.1.1-pre6'
STUNNEL_OPENSSLTLSTHREE='yes'
# default redis ports
STUNNEL_REDISSERVERCACCEPTPORT='7379'
STUNNEL_REDISSERVERCCONNECTPORT='6379'
STUNNEL_REDISCLIENTCACCEPTPORT='8379'
STUNNEL_REDISCLIENTCCONNECTPORT='7379'
# GCC 7.2.1 compile as march=native or march=x86-64
# default x86-64
MARCH_TARGETNATIVE='n'
# jemalloc
STUNNEL_JEMALLOC='y'
STUNNEL_JEMALLOCVER='5.0.1'
# use custom zlib 1.2.11 or cloudflare zlib 1.2.8
STUNNEL_CLOUDFLAREZLIB='y'
STUNNEL_CLOUDFLAREZLIBVER='1.2.8'
STUNNEL_CLOUDFLAREZLIBDEBUG='n'

# ssl cert variables
STUNNEL_HOSTNAME=$(hostname -f)
SELFSIGNEDSSL_C='US'
SELFSIGNEDSSL_ST='California'
SELFSIGNEDSSL_L='Los Angeles'
SELFSIGNEDSSL_O=''
SELFSIGNEDSSL_OU=''
CHECK_PCLMUL=$(gcc -c -Q -march=native --help=target | egrep '\[enabled\]|mtune|march' | grep 'mpclmul' | grep -o enabled)
#########################################################
# functions
#############
if [ ! -d /etc/systemd/system ]; then
  echo
  echo "error: CentOS 7 not detected"
  echo
  exit
fi

if [ ! -d "$DIR_TMP" ]; then
  echo
  echo "error: Centmin Mod Install no detected"
  echo
  exit
fi

if [[ ! "$CHECK_PCLMUL" = 'enabled' ]]; then
  echo
  echo "error: AES-NI pclmul cpu instruction support not detected"
  echo
  exit
fi

if [[ "$MARCH_TARGETNATIVE" = [yY] ]]; then
  MARCH_TARGET='native'
else
  MARCH_TARGET='x86-64'
fi

setup_csf() {
if [ -f /etc/csf/csf.conf ]; then
  # leave inbound to end user configuration
  if [[ ! "$(grep "$STUNNEL_REDISCLIENTCCONNECTPORT," /etc/csf/csf.conf)" ]]; then
    echo
    echo "CSF Firewall Port Whitelisting"
    # client outbound TCP/TCP6 7379
    sed -i "s/TCP_OUT = \"/TCP_OUT = \"$STUNNEL_REDISCLIENTCCONNECTPORT,/g" /etc/csf/csf.conf
    sed -i "s/TCP6_OUT = \"/TCP6_OUT = \"$STUNNEL_REDISCLIENTCCONNECTPORT,/g" /etc/csf/csf.conf
    csf -ra >/dev/null 2>&1
    echo
  fi
fi
}

install_openssl() {
  if [[ -f /opt/rh/devtoolset-7/root/usr/bin/gcc && -f /opt/rh/devtoolset-7/root/usr/bin/g++ ]]; then
    source /opt/rh/devtoolset-7/enable
    EXTRA_CFLAGS=" -Wimplicit-fallthrough=0 -fcode-hoisting"
    export CFLAGS="-march=${MARCH_TARGET} -fuse-ld=gold${EXTRA_CFLAGS}"
    export CXXFLAGS="$CFLAGS"
  fi
  cd "$DIR_TMP"
  mkdir -p stunnel-openssl
  cd stunnel-openssl
  if [ ! -f "openssl-${STUNNEL_OPENSSLVER}.tar.gz" ]; then
    echo "wget "https://www.openssl.org/source/openssl-${STUNNEL_OPENSSLVER}.tar.gz""
    wget "https://www.openssl.org/source/openssl-${STUNNEL_OPENSSLVER}.tar.gz"
  fi
  rm -rf "openssl-${STUNNEL_OPENSSLVER}"
  tar xzf "openssl-${STUNNEL_OPENSSLVER}.tar.gz"
  cd "openssl-${STUNNEL_OPENSSLVER}"
  make clean; make distclean
  s_openssldir="$STUNNEL_LIBDIR"
  CFLAGS="-march=${MARCH_TARGET} -fuse-ld=gold${EXTRA_CFLAGS}"
  CXXFLAGS="$CFLAGS"
  if [ "$STUNNEL_OPENSSLTLSTHREE" = [yY] ]; then
    ./config $CFLAGS -Wl,--enable-new-dtags,-rpath=${s_openssldir}/lib -lz --prefix=${s_openssldir} --openssldir=${s_openssldir} shared enable-ec_nistp_64_gcc_128 enable-zlib enable-tls1_3
  else
    ./config $CFLAGS -Wl,--enable-new-dtags,-rpath=${s_openssldir}/lib -lz --prefix=${s_openssldir} --openssldir=${s_openssldir} shared enable-ec_nistp_64_gcc_128 enable-zlib
  fi
  perl configdata.pm --dump
  make -j$(nproc)
  # make certs
  make install
}

setup_configfile() {
  if [[ "$STUNNEL_CLIENT" = [nN] ]]; then
# server config
cat > /etc/stunnel/stunnel.conf <<EOF
# chroot = /var/run/stunnel
cert = /etc/pki/tls/certs/stunnel.pem
pid = /var/run/stunnel/stunnel.pid
#pid = /stunnel.pid
output = /var/log/stunnel.log
#output = /stunnel.log
#debug = 7
#sslVersion = TLSv1.2

setuid = stunnel
setgid = stunnel
#ciphers = HIGH:!DH:!aNULL:!SSLv2:!SSLv3
ciphers = TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:HIGH:!DH:!aNULL:!SSLv2:!SSLv3
options = CIPHER_SERVER_PREFERENCE
#options = DONT_INSERT_EMPTY_FRAGMENTS
options = NO_SSLv3
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
socket = a:SO_REUSEADDR=yes
#compression = zlib

[redis-server]
client = no
#foreground = yes
accept = ${STUNNEL_REDISSERVERCACCEPTPORT}
connect = 127.0.0.1:${STUNNEL_REDISSERVERCCONNECTPORT}
cert = /etc/pki/tls/certs/stunnel.pem
CAfile = /etc/pki/tls/certs/stunnel.pem
verify = 3
sessionCacheSize = 50000
sessionCacheTimeout = 300

[redis-client]
client = yes
#foreground = yes
accept = 127.0.0.1:${STUNNEL_REDISCLIENTCACCEPTPORT}
connect = ${REDIS_REMOTEIP:-127.0.0.1}:${STUNNEL_REDISCLIENTCCONNECTPORT}
CAfile = /etc/pki/tls/certs/stunnel.pem
verify = 3
sessionCacheSize = 50000
sessionCacheTimeout = 300
EOF
  elif [[ "$STUNNEL_CLIENT" = [yY] ]]; then
# client config
cat > /etc/stunnel/stunnel.conf <<EOF
# chroot = /var/run/stunnel
cert = /etc/pki/tls/certs/stunnel.pem
pid = /var/run/stunnel/stunnel.pid
#pid = /stunnel.pid
output = /var/log/stunnel.log
#output = /stunnel.log
#debug = 7
#sslVersion = TLSv1.2

setuid = stunnel
setgid = stunnel
#ciphers = HIGH:!DH:!aNULL:!SSLv2:!SSLv3
ciphers = TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:HIGH:!DH:!aNULL:!SSLv2:!SSLv3
options = CIPHER_SERVER_PREFERENCE
#options = DONT_INSERT_EMPTY_FRAGMENTS
options = NO_SSLv3
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
#socket = a:SO_REUSEADDR=yes
#compression = zlib

[redis-client]
client = yes
#foreground = yes
accept = 127.0.0.1:${STUNNEL_REDISCLIENTCACCEPTPORT}
connect = ${REDIS_REMOTEIP:-127.0.0.1}:${STUNNEL_REDISCLIENTCCONNECTPORT}
CAfile = /etc/pki/tls/certs/stunnel.pem
verify = 3
sessionCacheSize = 50000
sessionCacheTimeout = 300
EOF
  fi
}

setup_peercerts() {
  pushd /etc/stunnel
  if [[ "$STUNNEL_CERTTYPE" = 'ecdsa' ]]; then
    # server
    openssl ecparam -out server.key -name prime256v1 -genkey
    openssl req -new -x509 -nodes -days 3650 -key server.key -out server.crt -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    openssl x509 -in server.crt -text -noout
    chmod 0600 server.key
    cat server.key > server.pem
    echo "" >> server.pem
    cat server.crt >> server.pem

    # client
    openssl ecparam -out client.key -name prime256v1 -genkey
    openssl req -new -x509 -nodes -days 3650 -key client.key -out client.crt -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    openssl x509 -in client.crt -text -noout
    chmod 0600 client.key
    cat client.key > client.pem
    echo "" >> client.pem
    cat client.crt >> client.pem
  else
    # server
    openssl genrsa -out server.key 2048
    openssl req -new -x509 -nodes -days 3650 -key server.key -out server.crt -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    openssl x509 -in server.crt -text -noout
    chmod 0600 server.key
    cat server.key > server.pem
    echo "" >> server.pem
    cat server.crt >> server.pem

    # client
    openssl genrsa -out client.key 2048
    openssl req -new -x509 -nodes -days 3650 -key client.key -out client.crt -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    openssl x509 -in client.crt -text -noout
    chmod 0600 client.key
    cat client.key > client.pem
    echo "" >> client.pem
    cat client.crt >> client.pem
  fi
  popd
}

setup_stunnel() {
  if [[ "$STUNNEL_CERTTYPE" = 'ecdsa' ]]; then
    # create stunnel.pem
    echo "creating ecdsa based /etc/pki/tls/certs/stunnel.pem"
    pushd /etc/pki/tls/certs/
    umask 77
    openssl ecparam -out stunnel.key -name prime256v1 -genkey
    openssl req -new -x509 -nodes -days ${STUNNEL_CERTEXPIRY} -key stunnel.key -out stunnel.crt -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    openssl x509 -in stunnel.crt -text -noout
    chmod 0600 stunnel.key
    cat stunnel.key > stunnel.pem
    echo "" >> stunnel.pem
    cat stunnel.crt >> stunnel.pem
    # rm -f stunnel.key stunnel.crt
    popd
    echo "created ecdsa based /etc/pki/tls/certs/stunnel.pem"
  else
    # create stunnel.pem
    echo "creating rsa based /etc/pki/tls/certs/stunnel.pem"
    pushd /etc/pki/tls/certs/
    umask 77
    PEM1='stunnel.key'
    PEM2='stunnel.crt'
    openssl req -newkey rsa:2048 -keyout $PEM1 -nodes -x509 -days ${STUNNEL_CERTEXPIRY} -out $PEM2 -subj "/C=${SELFSIGNEDSSL_C}/ST=${SELFSIGNEDSSL_ST}/L=${SELFSIGNEDSSL_L}/O=${SELFSIGNEDSSL_O}/OU=${SELFSIGNEDSSL_OU}/CN=${STUNNEL_HOSTNAME}"
    cat $PEM1 > stunnel.pem
    echo "" >> stunnel.pem
    cat $PEM2 >> stunnel.pem
    # rm -f $PEM1 $PEM2
    popd
    echo "created rsa based /etc/pki/tls/certs/stunnel.pem"
  fi
  # Create dhparam
  echo
  echo "openssl dhparam -out dhparam.pem 2048"
  openssl dhparam -out dhparam.pem 2048
  cat dhparam.pem >> stunnel.pem
  echo
  echo "check /etc/pki/tls/certs/stunnel.pem"
  echo "openssl x509 -in /etc/pki/tls/certs/stunnel.pem -text -noout"
  openssl x509 -in /etc/pki/tls/certs/stunnel.pem -text -noout
  echo
  setup_peercerts
  setup_configfile

  systemctl daemon-reload
  systemctl restart stunnelx.service
  systemctl enable stunnelx.service
  if [ -f /usr/bin/redis-cli ]; then
    echo
    echo "Check Redis profile connection"
    # echo "echo -n | /opt/stunnel-dep/bin/openssl -CAfile /etc/stunnel/server.pem -cert /etc/stunnel/server.crt -key /etc/stunnel/server.key"
    # echo -n | /opt/stunnel-dep/bin/openssl -CAfile /etc/stunnel/server.pem -cert /etc/stunnel/server.crt -key /etc/stunnel/server.key
    echo "echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/pki/tls/certs/stunnel.pem"
    echo -n | /opt/stunnel-dep/bin/openssl s_client -connect 127.0.0.1:7379 -CAfile /etc/pki/tls/certs/stunnel.pem
  fi
  echo
  systemctl status stunnelx.service
  echo
  stunnel -version
  echo
}

install_cfzlib() {
  if [[ "$STUNNEL_CLOUDFLAREZLIB" = [yY] && "$(cat /proc/cpuinfo | grep -o 'sse4_2' | uniq)" = 'sse4_2' && "$CHECK_PCLMUL" = 'enabled' ]]; then
    if [[ -f /opt/rh/devtoolset-7/root/usr/bin/gcc && -f /opt/rh/devtoolset-7/root/usr/bin/g++ ]]; then
      source /opt/rh/devtoolset-7/enable
      EXTRA_CFLAGS=" -Wimplicit-fallthrough=0 -fcode-hoisting"
      export CFLAGS="-march=${MARCH_TARGET} -fuse-ld=gold${EXTRA_CFLAGS}"
      export CXXFLAGS="$CFLAGS"
    fi
    install_cfzlibstartdir=$(pwd)
    echo
    echo "install zlib cloudflare..."
    echo
    pushd "$DIR_TMP"
    if [ ! -d "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}" ]; then
      git clone https://github.com/cloudflare/zlib "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}"
    elif [ -d "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}/.git" ]; then
      rm -rf "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}"
      git clone https://github.com/cloudflare/zlib "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}"
    fi
    pushd "stunnel-zlib-cloudflare-${STUNNEL_CLOUDFLAREZLIBVER}"
    # sed -i "s|\#define ZLIB_VERSION .*|\#define ZLIB_VERSION \"${STUNNEL_CLOUDFLAREZLIBVER}\"|" zlib.h
    # ldconfig
    make -f Makefile.in distclean
    ./configure --prefix=${STUNNEL_LIBDIR}
    # ./configure --prefix=${STUNNEL_LIBDIR} --static
    make -j$(nproc)
    # ps aufxwww > zlib-process.log
    if [[ "$STUNNEL_CLOUDFLAREZLIBDEBUG" = [Yy] ]]; then
      make -d install
      cfzlib_check=$?
      if [[ "$(uname -m)" = 'x86_64' ]]; then
          ln -sf ${STUNNEL_LIBDIR}/lib ${STUNNEL_LIBDIR}/lib64
      fi
    else
      make install
      cfzlib_check=$?
      if [[ "$(uname -m)" = 'x86_64' ]]; then
          ln -sf ${STUNNEL_LIBDIR}/lib ${STUNNEL_LIBDIR}/lib64
      fi
    fi
    popd
    # cd $install_cfzlibstartdir
    popd
    echo
    echo "zlib cloudflare installed"
    echo
  fi
}

install_stdzlib() {
  echo
  echo "install std zlib ..."
  echo
}

install_zlib() {
    if [[ "$STUNNEL_CLOUDFLAREZLIB" = [yY] && "$(cat /proc/cpuinfo | grep -o 'sse4_2' | uniq)" = 'sse4_2' && "$CHECK_PCLMUL" = 'enabled' ]]; then
        install_cfzlib
        if [[ "$cfzlib_check" -ne '0' ]]; then
            STUNNEL_CLOUDFLAREZLIB='n'
            install_stdzlib
        fi
    else
        install_stdzlib
    fi
}

jemalloc_printstats() {
  # https://github.com/jemalloc/jemalloc/wiki/Use-Case:-Basic-Allocator-Statistics
  if [[ ! -f /usr/bin/jemalloc5-stats && -f /opt/stunnel-dep/bin/jemalloc.sh ]]; then
    JEMALLOC_PATH='/opt/stunnel-dep'
    mkdir -p /root/tools
    JEMSTATS_CFILE='/root/tools/jemalloc5_stats_print.c'
    JEMSTATS_FILE='/root/tools/jemalloc5_stats_print'

cat >"$JEMSTATS_CFILE" <<JEM
#include <stdlib.h>
#include <jemalloc/jemalloc.h>

void
do_something(size_t i)
{

        // Leak some memory.
        malloc(i * 100);
}

int
main(int argc, char **argv)
{
        size_t i;

        for (i = 0; i < 1000; i++) {
                do_something(i);
        }

        // Dump allocator statistics to stderr.
        malloc_stats_print(NULL, NULL, NULL);

        return (0);
}
JEM

  gcc "$JEMSTATS_CFILE" -o $JEMSTATS_FILE -I${JEMALLOC_PATH}/include -L${JEMALLOC_PATH}/lib -Wl,-rpath,${JEMALLOC_PATH}/lib -ljemalloc
  if [ -f "$JEMSTATS_FILE" ]; then
    ln -sf "$JEMSTATS_FILE" /usr/bin/jemalloc5-stats
    chmod 0700 /usr/bin/jemalloc5-stats
  fi

  fi
}

install_jemalloc() {
  if [[ "$STUNNEL_JEMALLOC" = [yY] ]]; then
    echo
    cd "$DIR_TMP"
    if [ ! -f "jemalloc-${STUNNEL_JEMALLOCVER}.tar.gz" ]; then
      echo "wget https://github.com/jemalloc/jemalloc/archive/${STUNNEL_JEMALLOCVER}.tar.gz -O jemalloc-${STUNNEL_JEMALLOCVER}.tar.gz"
      wget https://github.com/jemalloc/jemalloc/archive/${STUNNEL_JEMALLOCVER}.tar.gz -O jemalloc-${STUNNEL_JEMALLOCVER}.tar.gz
    fi
    rm -rf "jemalloc-${STUNNEL_JEMALLOCVER}"
    tar xzf jemalloc-${STUNNEL_JEMALLOCVER}.tar.gz
    cd jemalloc-${STUNNEL_JEMALLOCVER}
    export CC="gcc"
    export CXX="g++"
    make clean; make distclean
    ./autogen.sh
    echo "./configure --disable-cxx --prefix=${STUNNEL_LIBDIR} --libdir=${STUNNEL_LIBDIR}/lib --includedir=${STUNNEL_LIBDIR}/include --with-version=${STUNNEL_JEMALLOCVER}-0-g1"
    ./configure --disable-cxx --prefix=${STUNNEL_LIBDIR} --libdir=${STUNNEL_LIBDIR}/lib --includedir=${STUNNEL_LIBDIR}/include --with-version=${STUNNEL_JEMALLOCVER}-0-g1
    # make -j$(nproc)
    make -j$(nproc) build_lib_shared
    make -j$(nproc) build_lib_static
    # make -j$(nproc) build_lib
    # make install
    make install_lib_shared
    make install_lib_static
    make install_include
    make install_bin
    make install_lib_pc
    echo "/opt/stunnel-dep/bin/jemalloc-config --version"
    /opt/stunnel-dep/bin/jemalloc-config --version
    jemalloc_printstats
    echo
  fi
}

install_stunnel() {
  if [[ -f /opt/rh/devtoolset-7/root/usr/bin/gcc && -f /opt/rh/devtoolset-7/root/usr/bin/g++ ]]; then
    unset CFLAGS
    unset CXXFLAGS
  fi
  cd "$DIR_TMP"
  if [ ! -f "stunnel-${STUNNEL_VERSION}.tar.gz" ]; then
    echo "wget "https://www.stunnel.org/downloads/beta/stunnel-${STUNNEL_VERSION}.tar.gz""
    wget "https://www.stunnel.org/downloads/beta/stunnel-${STUNNEL_VERSION}.tar.gz"
  fi
  rm -rf "stunnel-${STUNNEL_VERSION}"
  tar xzf "stunnel-${STUNNEL_VERSION}.tar.gz"
  cd stunnel-5.45
  make clean; make distclean
  LDFLAGS="-Wl,-rpath -Wl,${STUNNEL_LIBDIR}/lib -ljemalloc" ./configure --with-ssl=${STUNNEL_LIBDIR}
  make -j$(nproc)
  make install
  
  mkdir -p /etc/stunnel
  if [ -f /var/log/stunnel.log ]; then
    echo > /var/log/stunnel.log
  else
    touch /var/log/stunnel.log
  fi
  chmod 666 /var/log/stunnel.log
  useradd -r -m -d /var/run/stunnel -s /bin/false stunnel
  mkdir -p /var/run/stunnel/etc
  \cp -af /etc/hosts.allow /etc/hosts.deny /var/run/stunnel/etc
  chown -R stunnel:stunnel /var/run/stunnel
  echo "d /var/run/stunnel 0770 stunnel stunnel -" > /etc/tmpfiles.d/stunnel.conf
  
  mkdir -p /etc/systemd/system/stunnelx.service.d
  echo -e "[Service]\nLimitNOFILE=${STUNNEL_FD}\nLimitNPROC=${STUNNEL_FD}" > /etc/systemd/system/stunnelx.service.d/limit.conf
  # if [[ "$STUNNEL_JEMALLOC" = [yY] && -f /usr/lib64/libjemalloc.so.1 ]]; then
  #   echo -e "[Service]\nEnvironment=\"LD_PRELOAD = /usr/lib64/libjemalloc.so.1\"" > /etc/systemd/system/stunnelx.service.d/jemalloc.conf
  # fi

cat > /usr/lib/systemd/system/stunnelx.service <<EOF
[Unit]
Description=TLS tunnel for network daemons
After=syslog.target network.target

[Service]
ExecStart=/usr/local/bin/stunnel /etc/stunnel/stunnel.conf
Type=forking
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

stunnel_check() {
  echo
  "$STUNNEL_LIBDIR/bin/openssl" version -a
  echo
  /usr/local/bin/stunnel -version
  echo
}

#########################################################
case $1 in
  install )
    {
    install_zlib
    install_openssl
    install_jemalloc
    install_stunnel
    setup_stunnel
    setup_csf
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-install_${DT}.log"
    ;;
  update )
    {
    install_zlib
    install_openssl
    install_jemalloc
    install_stunnel
    systemctl daemon-reload
    systemctl restart stunnelx.service
    echo
    systemctl status stunnelx.service
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-update_${DT}.log"
    ;;
  update-certs )
    {
    setup_stunnel
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-update-certs_${DT}.log"
    ;;
  reinstall )
    {
    install_zlib
    install_openssl
    install_jemalloc
    install_stunnel
    setup_csf
    systemctl daemon-reload
    systemctl restart stunnelx.service
    echo
    systemctl status stunnelx.service
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-reinstall_${DT}.log"
    ;;
  check )
    {
    stunnel_check
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-check_${DT}.log"
    ;;
  openssl )
    {
    install_openssl
    } 2>&1 | tee "${CENTMINLOGDIR}/stunnel-openssl_${DT}.log"
    ;;
  * )
    echo
    echo "Usage:"
    echo "$0 {install|update|update-certs|reinstall|check|openssl"
    echo
    ;;
esac
exit
