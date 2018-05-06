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
VER='0.5'
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

# ssl cert variables
STUNNEL_HOSTNAME=$(hostname -f)
SELFSIGNEDSSL_C='US'
SELFSIGNEDSSL_ST='California'
SELFSIGNEDSSL_L='Los Angeles'
SELFSIGNEDSSL_O=''
SELFSIGNEDSSL_OU=''
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
    ./config $CFLAGS -Wl,--enable-new-dtags,-rpath=${s_openssldir}/lib --prefix=${s_openssldir} --openssldir=${s_openssldir} shared enable-ec_nistp_64_gcc_128 enable-tls1_3
  else
    ./config $CFLAGS -Wl,--enable-new-dtags,-rpath=${s_openssldir}/lib --prefix=${s_openssldir} --openssldir=${s_openssldir} shared enable-ec_nistp_64_gcc_128
  fi
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
ciphers = TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:HIGH:!DH:!aNULL:!SSLv2:!SSLv3
options = CIPHER_SERVER_PREFERENCE
#options = DONT_INSERT_EMPTY_FRAGMENTS
options = NO_SSLv3
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
#socket = a:SO_REUSEADDR=yes

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
ciphers = TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:HIGH:!DH:!aNULL:!SSLv2:!SSLv3
options = CIPHER_SERVER_PREFERENCE
#options = DONT_INSERT_EMPTY_FRAGMENTS
options = NO_SSLv3
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
#socket = a:SO_REUSEADDR=yes

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
  LDFLAGS="-Wl,-rpath -Wl,${STUNNEL_LIBDIR}/lib" ./configure --with-ssl=${STUNNEL_LIBDIR}
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
    install_openssl
    install_stunnel
    setup_stunnel
    setup_csf
    ;;
  update )
    install_openssl
    install_stunnel
    systemctl daemon-reload
    systemctl restart stunnelx.service
    echo
    systemctl status stunnelx.service
    ;;
  update-certs )
    setup_stunnel
    ;;
  reinstall )
    install_openssl
    install_stunnel
    setup_csf
    systemctl daemon-reload
    systemctl restart stunnelx.service
    echo
    systemctl status stunnelx.service
    ;;
  check )
    stunnel_check
    ;;
  openssl )
    install_openssl
    ;;
  * )
    echo
    echo "Usage:"
    echo "$0 {install|update|update-certs|reinstall|check|openssl"
    echo
    ;;
esac
exit
