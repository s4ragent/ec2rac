#/bin/bash
export LANG=C

INSTALL_LANG=ja
NUMBER_OF_NODES=10

RPMFORGE_URL="http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm"
EPEL_URL="http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm"

NETWORKS=("172.16.0.0" "172.17.0.0")
SUBNET_MASK="255.255.0.0"
NETWORK_NAME=("public" "priv")
SCAN_NAME="scan"

##device character ####
#/dev/sdi => /dev/xvdm#
ORACLE_HOME_DEVICE=m
ORACLE_HOME_EBS="/dev/xvd${ORACLE_HOME_DEVICE}"



#ORACLE_BASE and ORACLE_HOME edit it if need this path must under /u01 ##
MOUNT_PATH=/u01
ORA_ORACLE_BASE=${MOUNT_PATH}/app/oracle
ORA_ORACLE_HOME=${MOUNT_PATH}/app/oracle/product/12.1.0/dbhome_1
GRID_ORACLE_BASE=${MOUNT_PATH}/app/grid
GRID_ORACLE_HOME=${MOUNT_PATH}/app/12.1.0/grid
MEDIA_PATH=${MOUNT_PATH}/media
ORAINVENTORY=${MOUNT_PATH}/app/oraInventory

##oracle & grid (unix user) password ###
GRID_PASSWORD="P@ssw0rd"
ORACLE_PASSWORD="P@ssw0rd"

## scsi target name ###
SCSI_TARGET_NAME="iqn.2014-05.org.jpoug:server.crs"


installpackage ()
{
  rpm -ivh $RPMFORGE_URL
  rpm -ivh $EPEL_URL
  yum -y groupinstall "Desktop" "X Window System" "Japanese Support"
  yum -y install oracle-rdbms-server-12cR1-preinstall tigervnc-server screen nfs-utils dnsmasq scsi-target-utils iscsi-initiator-utils firefox.x86_64 xrdp expect tinc patch
  curl -L http://www.mail-archive.com/xrdp-devel@lists.sourceforge.net/msg00263/km-e0010411.ini -o ./km-e0010411.ini
  cp ./km-e0010411.ini /etc/xrdp/km-e0010411.ini
  cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-0411.ini
  cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0200411.ini 
  cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0210411.ini
  curl -L https://bugzilla.redhat.com/attachment.cgi?id=483052 -o ./tinc.init
  patch -p0 <<EOF
--- tinc.init.orig      2011-08-18 17:02:44.000000000 -0700
+++ tinc.init   2011-08-18 17:02:59.000000000 -0700
@@ -43,12 +43,9 @@
 #############################################################################
 # configuration & sanity checks

-#TINCD=/usr/sbin/tincd
-TINCD=/usr/local/sbin/tincd
-#TCONF=/etc/tinc
-TCONF=/usr/local/etc/tinc
-#TPIDS=/var/run
-TPIDS=/usr/local/var/run
+TINCD=/usr/sbin/tincd
+TCONF=/etc/tinc
+TPIDS=/var/run
 #DEBUG=-dddd
 #DEBUG=
 #DEBUG=--debug=5
EOF
  install -o root -g root -m 755 tinc.init /etc/init.d/tinc
  rm tinc.init
  rm km-e0010411.ini
  easy_install-2.6 awscli
  easy_install-2.6 boto
}


## $1 network number, $2 real/vip/priv $3 nodenumber ###
## Ex.   network 172,16.0.0 , 172.17.0.0 >>>##
## getip 0 vip 2 >>> 172.16.2.200 ###
getip ()
{
  if [ $SUBNET_MASK == "255.255.255.0" ] ; then
      SEGMENT=`echo ${NETWORKS[$1]} | perl -ne ' if (/([\d]+\.[\d]+\.[\d]+\.)/){ print $1}'`
      if [ $2 == "real" ] ; then
        IP=`expr $3 + 100`
        echo "${SEGMENT}${IP}"
      elif [ $2 == "vip" ] ; then
        IP=`expr $3 + 200`
        echo "${SEGMENT}${IP}"
      elif [ $2 == "scan" ] ; then
        echo "${SEGMENT}.30 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
        echo "${SEGMENT}.31 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
        echo "${SEGMENT}.32 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
      fi
  else
      SEGMENT=`echo ${NETWORKS[$1]} | perl -ne ' if (/([\d]+\.[\d]+\.)/){ print $1}'`
      if [ $2 == "real" ] ; then
        echo "${SEGMENT}${3}.100"
      elif [ $2 == "vip" ] ; then
        echo "${SEGMENT}${3}.200"
      elif [ $2 == "scan" ] ; then
        SEGMENT=`echo ${NETWORKS[$1]} | perl -ne ' if (/([\d]+\.[\d]+\.[\d]+\.)/){ print $1}'`
        echo "${SEGMENT}.30 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
        echo "${SEGMENT}.31 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
        echo "${SEGMENT}.32 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
      fi
  fi
}

getnodename ()
{
  echo "node"`printf "%.3d" $1`
}

setupdns ()
{
  NODELIST=`aws ec2 describe-instances --region ap-northeast-1 --query 'Reservations[].Instances[][?contains(Tags[?Key==\`Name\`].Value, \`node\`)==\`true\`].[NetworkInterfaces[].PrivateIpAddress]' --output text`
  SEGMENT=`echo ${NETWORKS[0]} | perl -ne ' if (/([\d]+\.[\d]+\.[\d]+\.)/){ print $1}'`

  echo "### scan entry ###" >> /etc/hosts
  getip 0 scan >> /etc/hosts

echo "### public,vip entry###" >> /etc/hosts
NODECOUNT=0
for i in $NODELIST ;
do
        echo "`getip 0 real $NODECOUNT` `getnodename $NODECOUNT`.${NETWORK_NAME[0]} `getnodename $NODECOUNT`" >> /etc/hosts
        echo "`getip 0 vip $NODECOUNT` `getnodename $NODECOUNT`-vip.${NETWORK_NAME[0]} `getnodename $NODECOUNT`-vip" >> /etc/hosts
        NODECOUNT=`expr $NODECOUNT + 1`
done

###enable dnsmasq####
chkconfig dnsmasq on
/etc/init.d/dnsmasq start

}

createtinc ()
{
for i in `seq 0 $NUMBER_OF_NODES`
do
        NODENAME=`getnodename $i`
        PORT=655

        for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
        do
                NETNAME=${NETWORK_NAME[$k]}
                mkdir -p /work/$NODENAME/$NETNAME/hosts
                cp /work/id_rsa /work/$NODENAME/$NETNAME/rsa_key.priv
                cat > /work/$NODENAME/$NETNAME/tinc.conf<<EOF
Name = $NODENAME
Interface = tap${k}
Mode = switch
BindToAddress * $PORT
EOF

                if [ $i != 0 ] ; then
                    echo "ConnectTo = `getnodename 0`.local" >> /work/$NODENAME/$NETNAME/tinc.conf
                fi


                cat > /work/$NODENAME/$NETNAME/hosts/$NODENAME<<EOF
Address = ${NODENAME}.local $PORT
Cipher = none
Digest = none

EOF
cat /work/id_rsa.pub.pem >> /work/$NODENAME/$NETNAME/hosts/$NODENAME

                if [ $k != 0 ] ; then
                    IP=`getprivip $i`
                else
                    IP=`getrealip $i`
                fi
                cat > /work/$NODENAME/$NETNAME/tinc-up<<EOF
#!/bin/sh
ifconfig \$INTERFACE ${IP} netmask $SUBNET_MASK
EOF

                cat > /work/$NODENAME/$NETNAME/tinc-down<<EOF
#!/bin/sh
ifconfig \$INTERFACE down
EOF

                chmod 755 /work/$NODENAME/$NETNAME/tinc-up
                chmod 755 /work/$NODENAME/$NETNAME/tinc-down

                PORT=`expr $PORT + 1`
        done
        NODECOUNT=`expr $NODECOUNT + 1`
done
}


createtinc2 ()
{
for i in `seq 0 $NUMBER_OF_NODES`
do
        NODENAME=`getnodename $i`
        PORT=655

        for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
        do
                NETNAME=${NETWORK_NAME[$k]}
                mkdir -p /work/$NODENAME/$NETNAME/hosts
                cat > /work/$NODENAME/$NETNAME/tinc.conf<<EOF
Name = $NODENAME
Interface = tap${k}
Mode = switch
BindToAddress * $PORT
EOF

                if [ $i != 0 ] ; then
                    echo "ConnectTo = `getnodename 0`.local" >> /work/$NODENAME/$NETNAME/tinc.conf
                fi


                cat > /work/$NODENAME/$NETNAME/hosts/$NODENAME<<EOF
Address = ${NODENAME}.local $PORT
Cipher = none
Digest = none
EOF

                if [ $i != 0 ] ; then
                    IP=`getprivip $i`
                else
                    IP=`getrealip $i`
                fi
                cat > /work/$NODENAME/$NETNAME/tinc-up<<EOF
#!/bin/sh
ifconfig \$INTERFACE ${IP} netmask $SUBNET_MASK
EOF

                cat > /work/$NODENAME/$NETNAME/tinc-down<<EOF
#!/bin/sh
ifconfig \$INTERFACE down
EOF

                chmod 755 /work/$NODENAME/$NETNAME/tinc-up
                chmod 755 /work/$NODENAME/$NETNAME/tinc-down

                expect -c "
spawn tincd --config /work/$NODENAME/$NETNAME -K
expect \"Please enter a file to save private RSA key to\"
sleep 3
send \"\r\n\"
expect \"Please enter a file to save public RSA key to\"
sleep 3
send \"\r\n\"
"

                CNT=`expr $CNT + 1`
                PORT=`expr $PORT + 1`
        done
        NODECOUNT=`expr $NODECOUNT + 1`
done
}

changehostname ()
{
  HOSTNAME=`getnodename $1`
  sed -i 's/hostname/#hostname/' /etc/rc.local
  cat > /etc/sysconfig/network <<EOF
NETWORKING=yes
NETWORKING_IPV6=no
HOSTNAME=${HOSTNAME}.${NETWORK_NAME[0]}
EOF
}

createsshkey ()
{
mkdir -p /work
ssh-keygen -t rsa -P "" -f /work/id_rsa
ssh-keygen -e -f id_rsa.pub >id_rsa.pub.pem
cat /work/id_rsa.pub >> /home/root/.ssh/authorized_keys
for i in `seq 0 $NUMBER_OF_NODES`
do
        echo "`getnodename $i`,`getip 0 real $i ` `cat /etc/ssh/ssh_host_rsa_key.pub`" >> /work/known_hosts
done
for user in oracle grid
do
        mkdir /home/$user/.ssh
        cat /work/id_rsa.pub >> /home/$user/.ssh/authorized_keys
        cp /work/id_rsa /home/$user/.ssh/
        cp /work/known_hosts /home/$user/.ssh
        chown -R ${user}.oinstall /home/$user/.ssh
        chmod 700 /home/$user/.ssh
        chmod 600 /home/$user/.ssh/*
done
}

createuser ()
{
userdel -r oracle
userdel -r grid
groupdel dba
groupdel oinstall
groupdel oper
groupdel asmadmin
groupdel asmdba
groupdel asmoper
##create user/group####
groupadd -g 501 oinstall
groupadd -g 502 dba
groupadd -g 503 oper
groupadd -g 1001 asmadmin
groupadd -g 1002 asmdba
groupadd -g 1003 asmoper
useradd -u 501 -m -g oinstall -G dba,oper,asmdba -d /home/oracle -s /bin/bash -c"Oracle Software Owner" oracle
useradd -u 1001 -m -g oinstall -G asmadmin,asmdba,asmoper -d /home/grid -s /bin/bash -c "Grid Infrastructure Owner" grid

##edit password ##
echo "grid:$GRID_PASSWORD" | chpasswd
echo "oracle:$ORACLE_PASSWORD" | chpasswd

### edit bash &bashrc ###
cat >> /home/oracle/.bashrc <<'EOF'
#this is for oracle install#
if [ -t 0 ]; then
   stty intr ^C
fi
EOF

cat >> /home/grid/.bashrc <<'EOF'
#this is for oracle install#
if [ -t 0 ]; then
   stty intr ^C
fi
EOF

cat >> /home/oracle/.bash_profile <<EOF
### for oracle install ####
export ORACLE_BASE=${ORA_ORACLE_BASE}
export ORACLE_HOME=${ORA_ORACLE_HOME}
EOF
cat >> /home/oracle/.bash_profile <<'EOF'
export TMPDIR=/tmp
export TEMP=/tmp
export PATH=$ORACLE_HOME/bin:$ORACLE_HOME/jdk/bin:${PATH}
export LD_LIBRARY_PATH=$ORACLE_HOME/lib
EOF
cat >> /home/grid/.bash_profile <<EOF
### for grid install####
export ORACLE_BASE=${GRID_ORACLE_BASE}
export ORACLE_HOME=${GRID_ORACLE_HOME}
EOF
cat >> /home/grid/.bash_profile <<'EOF'
export TMPDIR=/tmp
export TEMP=/tmp
export PATH=$ORACLE_HOME/bin:$ORACLE_HOME/jdk/bin:${PATH}
export LD_LIBRARY_PATH=$ORACLE_HOME/lib
EOF

#####Japanese Config#######
if [ $INSTALL_LANG = 'ja' ]; then

#edit bash_profile####
cat >> /home/oracle/.bash_profile <<'EOF'
export NLS_LANG=JAPANESE_JAPAN.UTF8
export LANG=ja_JP.UTF-8
export LC_ALL=ja_JP.UTF-8
EOF

cat >> /home/grid/.bash_profile <<'EOF'
export NLS_LANG=JAPANESE_JAPAN.UTF8
export LANG=ja_JP.UTF-8
export LC_ALL=ja_JP.UTF-8
EOF
fi
createsshkey
}

changelocale ()
{
if [ $INSTALL_LANG = 'ja' ]; then

###edit ZONE and system language##
sed -i 's/ZONE=.*/ZONE="Asia\/Tokyo"/' /etc/sysconfig/clock
cat > /etc/sysconfig/i18n <<EOF
LANG="ja_JP.UTF-8"
SYSFONT="lat0-sun16"
EOF
ln -sf /usr/share/zoneinfo/Asia/Tokyo /etc/localtime

fi
}

fdiskoraclehome ()
{
DISKSIZE=`fdisk -l ${ORACLE_HOME_EBS} | grep bytes | head -n 1 | perl -ne 'if(/B, ([\d]+) bytes/){print int($1/1024/1024)}'`

###create ORACLE_HOME####
sfdisk -uM ${ORACLE_HOME_EBS} <<EOF
0,${DISKSIZE},83
EOF
sleep 15
mkfs.ext3 -F ${ORACLE_HOME_EBS}1 
echo "${ORACLE_HOME_EBS}1               ${MOUNT_PATH}                    ext3    defaults        0 0" >> /etc/fstab
mkdir ${MOUNT_PATH}
mount ${MOUNT_PATH}
}

createoraclehome ()
{
mkdir -p ${GRID_ORACLE_BASE}
mkdir -p ${GRID_ORACLE_HOME}
mkdir -p ${MEDIA_PATH}
chown -R grid:oinstall ${MOUNT_PATH}
mkdir -p ${ORA_ORACLE_BASE}
chown oracle:oinstall ${ORA_ORACLE_BASE}
chmod -R 775 ${MOUNT_PATH}
}

case "$1" in 
  "installpackage" ) installpackage ;;
  "changehostname" )  changehostname ;;
  "createsshkey" ) createsshkey ;;
  "mountnfs" ) mountnfs ;;
  "createuser" ) createuser ;;
  "changelocale" ) changelocale ;;
  "fdiskoraclehome" ) fdiskoraclehome ;;
  "createoraclehome" ) createoraclehome ;;
  "setupdns" ) setupdns ;;
  "createtinc" ) createtinc ;;
  * ) echo "known option or no option" ;;
esac
