#/bin/bash
export LANG=C
SERVER="192.168.0.100"
NODELIST="192.168.0.101 192.168.0.102"
NODE=($NODELIST)
SERVERids=""
NODEids=""
NODEid=($NODEids)

INSTALL_LANG=ja
TMPL_NAME="RACTMPL"
KEY_NAME="oregon"
KEY_PAIR="${KEY_NAME}.pem"
PackageAmiId="ami-91a8dfa1"
RACSnapshotId="snap-7fada28c"
IamRole="root"
NODE_Instance_Type="m3.medium"
#NODE_Instance_Type="t1.micro"
SERVER_Instance_type="m3.medium"
#SERVER_Instance_type="t1.micro"

NodePrice="0.1"
ServerPrice="0.1"

SgNodeName="node-${TMPL_NAME}"
SgServerName="server-${TMPL_NAME}"

RPMFORGE_URL="http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm"
EPEL_URL="http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm"

NETWORKS=("172.16.0.0" "172.17.0.0")
SUBNET_MASK="255.255.240.0"
NETWORK_NAME=("public" "priv")
SCAN_NAME="scan"
ORACLE_HOME_SIZE=14
SWAP_SIZE=8
STORAGE_SIZE=30
STORAGE_FILE=/mnt/iscsi.img
SWAP_DEVICE="/dev/xvdb"
STORAGE_DEVICE="/dev/xvdb"
ORACLE_HOME_DEVICE="/dev/xvdc"

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

createclonepl()
{
  CLUSTER_NODES="{"
  NODECOUNT=1
  for i in $NODELIST ;
  do
        HOSTNAME=`getnodename $NODECOUNT`
        if [ $NODECOUNT != 1 ] ; then
                CLUSTER_NODES=${CLUSTER_NODES},
        fi
        CLUSTER_NODES=${CLUSTER_NODES}${HOSTNAME}
        NODECOUNT=`expr $NODECOUNT + 1`
  done
  CLUSTER_NODES=${CLUSTER_NODES}\}
cat >/home/grid/start.sh <<EOF
#!/bin/bash
ORACLE_BASE=$GRID_ORACLE_BASE
GRID_HOME=$GRID_ORACLE_HOME
THIS_NODE=\`hostname -s\`
E01=ORACLE_BASE=\${ORACLE_BASE}
E02=ORACLE_HOME=\${GRID_HOME}
E03=ORACLE_HOME_NAME=OraGridHome1
E04=INVENTORY_LOCATION=$ORAINVENTORY
C01="CLUSTER_NODES=$CLUSTER_NODES"
C02="LOCAL_NODE=\$THIS_NODE"
perl \${GRID_HOME}/clone/bin/clone.pl -silent \$E01 \$E02 \$E03 \$E04 \$C01 \$C02
EOF

chmod 755 /home/grid/start.sh
chown grid.oinstall /home/grid/start.sh

cat >/home/oracle/start.sh <<EOF
#!/bin/bash
ORACLE_BASE=$ORA_ORACLE_BASE
ORACLE_HOME=$ORA_ORACLE_HOME
cd \$ORACLE_HOME/clone
THIS_NODE=\`hostname -s\`

E01=ORACLE_HOME=$ORA_ORACLE_HOME
E02=ORACLE_HOME_NAME=OraDBRAC
E03=ORACLE_BASE=$ORA_ORACLE_BASE
C01="-O CLUSTER_NODES=$CLUSTER_NODES"
C02="-O LOCAL_NODE=\$THIS_NODE"
perl \$ORACLE_HOME/clone/bin/clone.pl \$E01 \$E02 \$E03 \$C01 \$C02
EOF

chmod 755 /home/oracle/start.sh
chown oracle.oinstall /home/oracle/start.sh
}

createswap(){
  if [ "$1" != "0" ] ; then
        umount -f $SWAP_DEVICE;mkswap -f $SWAP_DEVICE;swapon $SWAP_DEVICE
        echo "umount -f $SWAP_DEVICE;mkswap -f $SWAP_DEVICE;swapon $SWAP_DEVICE" >> /etc/rc.local
        echo "$SWAP_DEVICE swap swap defaults 0 0 " >> /etc/fstab
  fi
}

setupiscsi(){
if [ $1 = 0 ]; then
    umount -f $STORAGE_DEVICE
    sfdisk -uM ${STORAGE_DEVICE} <<EOF
,,83
EOF
    sleep 15
    cat > /etc/tgt/targets.conf <<EOF
<target ${SCSI_TARGET_NAME}>
# List of files to export as LUNs
        <backing-store ${STORAGE_DEVICE}1>
                lun 1
        </backing-store>
initiator-address ALL
</target>
EOF

sed -i 's/\(.*cloudconfig\)/#\1/' /etc/fstab
/etc/init.d/tgtd start
chkconfig tgtd on
tgt-admin --show

else
        /etc/init.d/iscsi start
        iscsiadm --mode discovery --type sendtargets -p ${SERVER}
        iscsiadm --mode node --targetname ${SCSI_TARGET_NAME} --login
        chkconfig iscsi on
        /etc/init.d/iscsi restart
        sleep 15
        echo 'KERNEL=="sd[a-d]*",ACTION=="add|change",OWNER="grid",GROUP="asmadmin",MODE="0660"' > /etc/udev/rules.d/99-oracle.rules
        #initialize asmdisk if nodenumber=1 ####        
        if [ $1 = 1 ]; then     
                sfdisk /dev/sda << EOF
,,83
EOF
                dd if=/dev/zero of=/dev/sda1 bs=1M count=100
        fi
fi
}



copyfile()
{
SERVER_AND_NODE="$SERVER $NODELIST"
for i in $SERVER_AND_NODE ;
do
        ssh -i $KEY_PAIR -o "StrictHostKeyChecking no" root@$i "date"
        scp -i $KEY_PAIR -r $1 root@$i:/root
done
}

installpackage ()
{
  rpm -ivh $RPMFORGE_URL
  rpm -ivh $EPEL_URL
  yum -y groupinstall "Desktop" "X Window System" "Japanese Support"
  yum -y install unzip oracle-rdbms-server-12cR1-preinstall tigervnc-server screen nfs-utils dnsmasq scsi-target-utils iscsi-initiator-utils firefox.x86_64 xrdp expect tinc patch
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
## getip 0 vip 2 >>> 172.16.2.2 ###
getip ()
{
  SEGMENT=`echo ${NETWORKS[$1]} | perl -ne ' if (/([\d]+\.[\d]+\.)/){ print $1}'`
  if [ $2 == "real" ] ; then
    echo "${SEGMENT}1.${3}"
  elif [ $2 == "vip" ] ; then
    echo "${SEGMENT}2.${3}"
  elif [ $2 == "scan" ] ; then
    echo "${SEGMENT}0.30 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
    echo "${SEGMENT}0.31 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
    echo "${SEGMENT}0.32 ${SCAN_NAME}.${NETWORK_NAME[0]} ${SCAN_NAME}"
  fi
}

getnodename ()
{
  echo "node"`printf "%.3d" $1`
}

setupnodelist()
{
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  #NODELIST=`aws ec2 describe-instances --region $Region --query 'Reservations[].Instances[?contains(KeyName,\`node\`)==\`true\`].[NetworkInterfaces[].PrivateIpAddress]' --output text`
  #NODELIST=`aws ec2 describe-instances --region $Region --query "Reservations[].Instances[][?contains(NetworkInterfaces[].Groups[].GroupName,\\\`$SgNodeName\\\`)==\\\`true\\\`].[NetworkInterfaces[].PrivateIpAddress]" --output text`
  SgNodeId=`aws ec2 describe-security-groups --region $Region --filter "Name=group-name,Values=$SgNodeName" --query 'SecurityGroups[].GroupId' --output text`
  NODEOBJ=`aws ec2 describe-instances --region $Region --filter "Name=instance.group-id,Values=$SgNodeId" --query 'Reservations[].Instances[].[InstanceId,[NetworkInterfaces[].PrivateIpAddress]]' --output text`
  NODEOBJ=`echo $NODEOBJ`
  NODELIST=""
  NODEids=""
  CNT=0
  for i in $NODEOBJ ;
  do
      if [ $CNT == 0 ]; then
        NODEids="$i"      
      elif [ $CNT == 1 ]; then
        NODELIST="$i"
      elif [ `expr $CNT % 2` == 0 ]; then
        NODEids="$NODEids $i"
      else
        NODELIST="$NODELIST $i"
      fi
      CNT=`expr $CNT + 1`
  done
  
  
  #SERVER=`aws ec2 describe-instances --region $Region --query "Reservations[].Instances[][?contains(NetworkInterfaces[].Groups[].GroupName,\\\`$SgServerName\\\`)==\\\`true\\\`].[NetworkInterfaces[].PrivateIpAddress]" --output text`
  SgServerId=`aws ec2 describe-security-groups --region $Region --filter "Name=group-name,Values=$SgServerName" --query 'SecurityGroups[].GroupId' --output text`
  SERVEROBJ=`aws ec2 describe-instances --region $Region --filter "Name=instance.group-id,Values=$SgServerId" --query 'Reservations[].Instances[].[InstanceId,[NetworkInterfaces[].PrivateIpAddress]]' --output text`
  SERVEROBJ=`echo $SERVEROBJ`
  SERVER=""
  SERVERids=""
  CNT=0
  for i in $SERVEROBJ ;
  do
      if [ `expr $CNT % 2` == 0 ]; then
        SERVERids="$i"
      else
        SERVER="$i"
      fi
      CNT=`expr $CNT + 1`
  done
  NODE=($NODELIST)
  NODEid=($NODEids)
}

clone()
{
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  #deviceJson=[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":25,\"DeleteOnTermination\":true,\"VolumeType\":\"standard\"}},{\"DeviceName\":\"/dev/sdb\",\"VirtualName\":\"ephemeral0\"}]
  #InstanceId=`curl -s http://169.254.169.254/latest/meta-data/instance-id`
  InstanceId=$1
  DATE=`date "+%Y%m%d%H%M"`
  #AmiId=`aws ec2 create-image --instance-id $InstanceId --name $TMPL_NAME-$DATE --no-reboot --region $Region --block-device-mappings $deviceJson --output text`
  AmiId=`aws ec2 create-image --instance-id $InstanceId --name "$1-$DATE" --no-reboot --region $Region --query 'ImageId' --output text`
  State=`aws ec2 describe-images --region $Region --image-id $AmiId --query 'Images[].State[]' --output text`
  while [ $State = "pending" ]
  do
    sleep 10
    State=`aws ec2 describe-images --region $Region --image-id $AmiId --query 'Images[].State[]' --output text`
  done
  echo $AmiId
  #sed -i "s/^AmiId.*/AmiId=\"$AmiId\"/" $0
}

createsnapshot()
{
  InstanceId=$1
  DeviceName=$2
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  #VolumeId=`aws ec2 describe-volumes --region $Region --query "Volumes[].Attachments[][?Device==\\\`$DeviceName\\\`][?InstanceId==\\\`$InstanceId\\\`].VolumeId" --output text`
  VolumeId=`aws ec2 describe-volumes --region $Region --filters "Name=attachment.instance-id,Values=$InstanceId" "Name=attachment.device,Values=$DeviceName" --query "Volumes[].Attachments[].VolumeId" --output text`
  SnapshotId=`aws ec2 create-snapshot --region $Region --volume-id $VolumeId --query 'SnapshotId' --output text`
  State=`aws ec2 describe-snapshots --region $Region --snapshot-ids $SnapshotId --query 'Snapshots[].State[]' --output text`
  while [ $State = "pending" ]
  do
    sleep 10
    State=`aws ec2 describe-snapshots --region $Region --snapshot-ids $SnapshotId --query 'Snapshots[].State[]' --output text`
  done
  echo $SnapshotId
}  

listinstances()
{
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  aws ec2 describe-instances --region $Region --query 'Reservations[].Instances[].[InstanceId,NetworkInterfaces[]."PrivateIpAddress"]' --output text
}

listami()
{
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  aws ec2 describe-images --region $Region --owner self --query 'Images[].[Name,ImageId]' --output text
}

prestartinstances(){
  InstanceId=`curl -s http://169.254.169.254/latest/meta-data/instance-id`
  Az=`curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone`
  Region=`echo $Az | perl -lne 'print substr($_,0,-1)'`
  VpcSubnet=`aws ec2 describe-instances --region $Region --instance-id $InstanceId --query 'Reservations[].Instances[].[VpcId,SubnetId]' --output text`
  VpcId=`echo $VpcSubnet | awk -F " " '{print $1}'`
  SubnetId=`echo $VpcSubnet | awk -F " " '{print $2}'`
  aws ec2 delete-security-group --group-name $SgNodeName --region $Region
  aws ec2 delete-security-group --group-name $SgServerName --region $Region
  SgNodeId=`aws ec2 create-security-group --group-name $SgNodeName --description "$SgNodeName"  --vpc-id $VpcId --region $Region --query 'GroupId' --output text`
  SgServerId=`aws ec2 create-security-group --group-name $SgServerName --description "$SgServerName"  --vpc-id $VpcId --region $Region --query 'GroupId' --output text`
  
  #SgNodeId=`aws ec2 describe-security-groups --region $Region --query "SecurityGroups[][?contains(GroupName,\\\`$SgNodeName\\\`)==\\\`true\\\`].[GroupId]" --output text`
  #SgServerId=`aws ec2 describe-security-groups --region $Region --query "SecurityGroups[][?contains(GroupName,\\\`$SgServerName\\\`)==\\\`true\\\`].[GroupId]" --output text`
  
  MyIp=`ifconfig eth0 | grep 'inet addr' | awk -F '[: ]' '{print $13}'`
  MyNetwork=`echo $MyIp | perl -ne ' if (/([\d]+\.[\d]+\.)/){ print $1}'`
  MyNetwork="${MyNetwork}0.0"
  aws ec2 authorize-security-group-ingress --group-id $SgNodeId --cidr $MyNetwork/16 --protocol -1 --port -1 --region $Region 
  aws ec2 authorize-security-group-ingress --group-id $SgServerId --cidr $MyNetwork/16 --protocol -1 --port -1 --region $Region 
  
  if [ ! -e $KEY_PAIR ] ; then
        aws ec2 create-key-pair --region $Region --key-name $KEY_NAME --query 'KeyMaterial' --output text > $KEY_PAIR
  fi

}

requestspotinstances(){
  ServerAmiId=$PackageAmiId
  Server_Count=$1
  NodeAmiId=$PackageAmiId
  Node_Count=$2
  prestartinstances
  #JSON={\"IPs\":{\"S\":\"$NODELIST\"}}
  NodedeviceJson=\"BlockDeviceMappings\":[{\"DeviceName\":\"$ORACLE_HOME_DEVICE\",\"Ebs\":{\"VolumeSize\":$ORACLE_HOME_SIZE,\"SnapshotId\":\"$RACSnapshotId\",\"DeleteOnTermination\":true,\"VolumeType\":\"standard\"}},{\"DeviceName\":\"$SWAP_DEVICE\",\"VirtualName\":\"ephemeral0\"}]
  ServerdeviceJson=\"BlockDeviceMappings\":[{\"DeviceName\":\"$STORAGE_DEVICE\",\"VirtualName\":\"ephemeral0\"}]
  NodeJson={\"ImageId\":\"${NodeAmiId}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${NODE_Instance_Type}\",$NodedeviceJson,\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"$SgNodeId\"]}
  ServerJson={\"ImageId\":\"${ServerAmiId}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${SERVER_Instance_type}\",$ServerdeviceJson,\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"$SgServerId\"]}

  aws ec2 request-spot-instances --spot-price $NodePrice --region $Region --launch-group $SgNodeName --launch-specification $NodeJson --instance-count $Node_Count
  aws ec2 request-spot-instances --spot-price $ServerPrice --region $Region --launch-group $SgServerName --launch-specification $ServerJson --instance-count $Server_Count

}


startinstances(){
  ServerAmiId=$1
  ServerAmiId=$PackageAmiId
  Server_Count=$1
  NodeAmiId=$PackageAmiId
  Node_Count=$2
  NodedeviceJson=[{\"DeviceName\":\"$ORACLE_HOME_DEVICE\",\"Ebs\":{\"VolumeSize\":$ORACLE_HOME_SIZE,\"DeleteOnTermination\":true,\"VolumeType\":\"standard\"}},{\"DeviceName\":\"$SWAP_DEVICE\",\"VirtualName\":\"ephemeral0\"}]
  ServerdeviceJson=[{\"DeviceName\":\"$STORAGE_DEVICE\",\"Ebs\":{\"VolumeSize\":$STORAGE_SIZE,\"DeleteOnTermination\":true,\"VolumeType\":\"standard\"}}]
  
  prestartinstances
  aws ec2 run-instances --region $Region --image-id $NodeAmiId --key-name $KEY_NAME --subnet-id $SubnetId --security-group-ids $SgNodeId --block-device-mappings $NodedeviceJson --iam-instance-profile Name=$IamRole --instance-type $NODE_Instance_Type --count $Node_Count
  aws ec2 run-instances --region $Region --image-id $ServerAmiId --key-name $KEY_NAME --subnet-id $SubnetId --security-group-ids $SgServerId --block-device-mappings $ServerdeviceJson --instance-type $SERVER_Instance_type --count $Server_Count
}


stopinstances()
{
  setupnodelist
  aws ec2 stop-instances --region $Region --instance-ids $NODEids $SERVERids 
}

terminateinstances()
{
  setupnodelist
  aws ec2 terminate-instances --region $Region --instance-ids $NODEids $SERVERids 
}

setupkernel()
{
sed -i  's/HWADDR=/#HWADDR=/' /etc/sysconfig/network-scripts/ifcfg-eth0

###selinux disable####
sed -i  's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
setenforce 0


##disable firewall####
chkconfig iptables off
/etc/init.d/iptables stop

###disable NetworkManager##
chkconfig NetworkManager off
/etc/init.d/NetworkManager stop

## PAM ###
echo "session required pam_limits.so" >> /etc/pam.d/login
###kernel parameter ####

#cat >> /etc/sysctl.conf <<EOF
#this is for oracle install#
#net.ipv4.ip_local_port_range = 9000 65500
#net.core.rmem_default = 262144
#net.core.rmem_max = 4194304
#net.core.wmem_default = 262144
#net.core.wmem_max = 1048576
#kernel.shmmax = ${MEMSIZE}
#kernel.shmall = 4294967296
#kernel.shmmni = 4096
#kernel.sem = 250 32000 100 128
#fs.file-max = 6815744
#fs.aio-max-nr = 1048576
#EOF

##### limits.conf #####
sed -i 's/oracle/#oracle/' /etc/security/limits.conf
cat >> /etc/security/limits.conf <<EOF
#this is for oracle install#
oracle - nproc 16384
oracle - nofile 65536
oracle soft stack 10240
grid - nproc 16384
grid - nofile 65536
grid soft stack 10240
EOF

##disable ntp####
chkconfig ntpd off
mv /etc/ntp.conf /etc/ntp.conf.original
rm /var/run/ntpd.pid
}

setupdns ()
{
        
  if [ "$1" != "0" ] ; then
        #echo "nameserver ${SERVER}" >/etc/resolv.conf
        #echo "nameserver ${SERVER}" >/etc/resolv.tmpl
        #sed -i "6i cp -f /etc/resolv.tmpl /etc/resolv.conf" /etc/rc.local
        echo "supersede domain-name-servers ${SERVER};" >> /etc/dhcp/dhclient-eth0.conf
  else
    SERVER_AND_NODE="$SERVER $NODELIST"
    SEGMENT=`echo ${NETWORKS[0]} | perl -ne ' if (/([\d]+\.[\d]+\.[\d]+\.)/){ print $1}'`
    echo "### scan entry ###" >> /etc/hosts
    getip 0 scan >> /etc/hosts
    echo "### public,vip entry###" >> /etc/hosts
    NODECOUNT=0
    for i in $SERVER_AND_NODE ;
    do
        echo "`getip 0 real $NODECOUNT` `getnodename $NODECOUNT`.${NETWORK_NAME[0]} `getnodename $NODECOUNT`" >> /etc/hosts
        echo "`getip 0 vip $NODECOUNT` `getnodename $NODECOUNT`-vip.${NETWORK_NAME[0]} `getnodename $NODECOUNT`-vip" >> /etc/hosts
        NODECOUNT=`expr $NODECOUNT + 1`
    done
    ###enable dnsmasq####
    chkconfig dnsmasq on
    /etc/init.d/dnsmasq start
  fi        


}

sshkeyscan()
{
  setupnodelist
  SERVER_AND_NODE="$SERVER $NODELIST"
  for i in $SERVER_AND_NODE ;
  do
        ssh-keyscan -T 120 $i
  done
}


pretincconf()
{
  rm -rf ./dummy
  mkdir -p ./dummy/hosts
  cat > ./dummy/tinc.conf <<EOF
Name = dummy
Interface = tap0
Mode = switch
BindToAddress * 655
ConnectTo = `getnodename 0`
EOF
  cat > ./dummy/hosts/dummy<<EOF
Address = 127.0.0.1 655
Cipher = none
Digest = none
EOF
  expect -c "
spawn tincd --config ./dummy -K
expect \"Please enter a file to save private RSA key to\"
sleep 3
send \"\r\n\"
expect \"Please enter a file to save public RSA key to\"
sleep 3
send \"\r\n\"
"
}

createtincconf()
{
  SERVER_AND_NODE="$SERVER $NODELIST"
  /etc/init.d/tinc stop
  sleep 5
  rm -rf /etc/tinc
PORT=655
NODENAME=`getnodename $1`
for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
do
    NETNAME=${NETWORK_NAME[$k]}     
    mkdir -p /etc/tinc/$NETNAME/hosts
    echo $NETNAME >> /etc/tinc/nets.boot
    echo "tinc          ${PORT}/tcp             #TINC" >> /etc/services
    echo "tinc          ${PORT}/udp             #TINC" >> /etc/services
    cp ./dummy/tinc.conf /etc/tinc/$NETNAME/tinc.conf
    sed -i "s/^Name =.*/Name = $NODENAME/" /etc/tinc/$NETNAME/tinc.conf
    sed -i "s/^Interface = .*/Interface = tap${k}/" /etc/tinc/$NETNAME/tinc.conf
    sed -i "s/^BindToAddress.*/BindToAddress \* $PORT/" /etc/tinc/$NETNAME/tinc.conf
    
    cp ./dummy/rsa_key.priv /etc/tinc/$NETNAME/rsa_key.priv
    
    IP=`getip $k real $1`
    cat > /etc/tinc/$NETNAME/tinc-up<<EOF
#!/bin/sh
ifconfig \$INTERFACE ${IP} netmask $SUBNET_MASK
EOF

    cat > /etc/tinc/$NETNAME/tinc-down<<EOF
#!/bin/sh
ifconfig \$INTERFACE down
EOF

    chmod 755 /etc/tinc/$NETNAME/tinc-up
    chmod 755 /etc/tinc/$NETNAME/tinc-down
    
    NODECOUNT=0
    for i in $SERVER_AND_NODE ;
    do
      NODENAME2=`getnodename $NODECOUNT`
      cp ./dummy/hosts/dummy /etc/tinc/$NETNAME/hosts/$NODENAME2
      sed -i "s/^Address = .*/Address = $i $PORT/" /etc/tinc/$NETNAME/hosts/$NODENAME2
      NODECOUNT=`expr $NODECOUNT + 1`
    done
    PORT=`expr $PORT + 1`
done
chkconfig tinc on
/etc/init.d/tinc start
}

createclusterlist()
{
NODECOUNT=1
for i in $NODELIST ;
do
    NODENAME=`getnodename $NODECOUNT`
    echo "${NODENAME} ${NODENAME}-vip" >> /tmp/clusterlist.ccf
    NODECOUNT=`expr $NODECOUNT + 1`
done
chmod 777 /tmp/clusterlist.ccf
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
rm -rf ./id_rsa*
ssh-keygen -t rsa -P "" -f ./id_rsa
cat ./id_rsa.pub >>  .ssh/authorized_keys
for i in `seq 0 200` ;
do
  echo "`getnodename $i`,`getip 0 real $i` `cat /etc/ssh/ssh_host_rsa_key.pub`" >> ./known_hosts
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

for user in oracle grid
do
        mkdir /home/$user/.ssh
        cat ./id_rsa.pub >> /home/$user/.ssh/authorized_keys
        cp ./id_rsa /home/$user/.ssh/
        cp ./known_hosts /home/$user/.ssh
        chown -R ${user}.oinstall /home/$user/.ssh
        chmod 700 /home/$user/.ssh
        chmod 600 /home/$user/.ssh/*
done

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

fdiskoraclehome()
{
  if [ "$1" != "0" ] ; then
    sfdisk -uM ${ORACLE_HOME_DEVICE} <<EOF
,,83
EOF
    sleep 15
    mkfs.ext3 -F ${ORACLE_HOME_DEVICE}1
  fi
}

mountoraclehome()
{
  
  if [ "$1" != "0" ] ; then
    echo "${ORACLE_HOME_DEVICE}1               ${MOUNT_PATH}                    ext3    defaults        0 0" >> /etc/fstab
    mkdir ${MOUNT_PATH}
    mount ${MOUNT_PATH}
  fi
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

createtmpl()
{
  installpackage
  changelocale
  createsshkey
  createuser
  setupkernel
  pretincconf
  InstanceId=`curl -s http://169.254.169.254/latest/meta-data/instance-id`
  AmiId=`clone $InstanceId`
  sed -i "s/^PackageAmiId=.*/PackageAmiId=\"$AmiId\"/" $0
}


createclonebase()
{
  ssh -i $KEY_PAIR -o "StrictHostKeyChecking no" root@${NODE[0]} "$GRID_ORACLE_HOME/bin/crsctl stop crs;rm -rf $ORAINVENTORY"
  InstanceId=${NODEid[0]}
  SnapShotId=`createsnapshot $InstanceId $ORACLE_HOME_DEVICE`
  sed -i "s/^RACSnapshotId=.*/RACSnapshotId=\"$SnapShotId\"/" $0
}

setupnodeforclone()
{
  changelocale
  chkconfig xrdp on
  changehostname $1
  setupdns $1
  createtincconf $1
  createswap $1
  setupiscsi $1
  mountoraclehome $1
  cleangridhome
  createclusterlist
  createclonepl
}

cleangridhome()
{


  mkdir -p $ORAINVENTORY
  chown grid:oinstall $ORAINVENTORY
  
  HOSTNAME=`getnodename 1`
  cd $GRID_ORACLE_HOME
  rm -rf log/$HOSTNAME
  rm -rf gpnp/$HOSTNAME
  find gpnp -type f -exec rm -f {} \;
  rm -rf cfgtoollogs/*
  rm -rf crs/init/*
  rm -rf cdata/*
  rm -rf crf/*
  rm -rf network/admin/*.ora
  rm -rf crs/install/crsconfig_params
  find . -name '*.ouibak' -exec rm {} \;
  find . -name '*.ouibak.1' -exec rm {} \;
  rm -rf root.sh*
  rm -rf rdbms/audit/*
  rm -rf rdbms/log/*
  rm -rf inventory/backup/*
}


setupnodeforclone()
{
  changelocale
  chkconfig xrdp on
  changehostname $1
  setupdns $1
  createtincconf $1
  createswap $1
  setupiscsi $1
  mountoraclehome $1
  cleangridhome
  createclusterlist
  createclonepl
}

cleangridhome2()
{
  OLD_IFS=$IFS
  IFS='/'
  set -- $GRID_ORACLE_HOME
  IFS=$OLD_IFS
  for i in "$@"
  do
    if [ "$i" != "" ] ; then
        CHMODPATH=${CHMODPATH}"/"${i}
        chown grid:oinstall $CHMODPATH
    fi
  done

  mkdir -p $ORAINVENTORY
  chown grid:oinstall $ORAINVENTORY
  mkdir -p $GRID_ORACLE_BASE
  chown grid:oinstall $GRID_ORACLE_BASE
  chown -R grid:oinstall $GRID_ORACLE_HOME
  chmod u+s $GRID_ORACLE_HOME/bin/oracle
  chmod g+s $GRID_ORACLE_HOME/bin/oracle
  chmod u+s $GRID_ORACLE_HOME/bin/extjob
  chmod u+s $GRID_ORACLE_HOME/bin/jssu
  chmod u+s $GRID_ORACLE_HOME/bin/oradism
  
  #HOSTNAME=`getnodename 1`
  #cd $GRID_ORACLE_HOME
  #rm -rf log/$HOSTNAME
  #rm -rf gpnp/$HOSTNAME
  #find gpnp -type f -exec rm -f {} \;
  #rm -rf cfgtoollogs/*
  #rm -rf crs/init/*
  #rm -rf cdata/*
  #rm -rf crf/*
  #rm -rf network/admin/*.ora
  #rm -rf crs/install/crsconfig_params
  #find . -name '*.ouibak' -exec rm {} \;
  #find . -name '*.ouibak.1' -exec rm {} \;
  #rm -rf root.sh*
  #rm -rf rdbms/audit/*
  #rm -rf rdbms/log/*
  #rm -rf inventory/backup/*
}

setupnode()
{
  changehostname $1
  setupdns $1
  createtincconf $1
  createswap $1
  setupiscsi $1
  fdiskoraclehome $1
  mountoraclehome $1
  createoraclehome
}

setupallforclonep1(){
  #startupinnstance
  setupnodelist
  sed -i "s/^NODELIST=.*/NODELIST=\"$NODELIST\"/" $0
  sed -i "s/^NODEids=.*/NODEids=\"$NODEids\"/" $0
  sed -i "s/^SERVER=.*/SERVER=\"$SERVER\"/" $0
  copyfile $0
  SERVER_AND_NODE="$SERVER $NODELIST"
  
  
  ssh -i $KEY_PAIR -o "StrictHostKeyChecking no" root@$SERVER "sh -x $0 setupnodeforclone 0;reboot"
  sleep 120
  NODECOUNT=1
  for i in $NODELIST ;
  do
        ssh -f -t -i $KEY_PAIR -o "StrictHostKeyChecking no" root@$i "sh -x $0 setupnodeforclone $NODECOUNT;reboot"
        NODECOUNT=`expr $NODECOUNT + 1`
  done
  sleep 120
  for i in $NODELIST ;
  do
        ssh -i $KEY_PAIR -t -t -f root@$i "sudo -u grid /home/grid/start.sh;$ORAINVENTORY/orainstRoot.sh"
  done
  echo "execute ps -elf | grep ssh  and no proccess remain plese execute grid_home/crs/config/config.sh and later setupallforclonep2"
}

setupallforclonep5(){
  for i in $NODELIST ;
  do
        ssh -i $KEY_PAIR -t -t -f root@$i "sudo -u oracle /home/oracle/start.sh;$ORA_ORACLE_HOME/root.sh -silent"
  done
}


setupallforclonep2()
{
  ssh -i $KEY_PAIR root@${NODE[0]} "$GRID_ORACLE_HOME/crs/install/rootcrs.pl -deconfig -force -verbose;$GRID_ORACLE_HOME/root.sh -silent;ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat" > 1.log
}
setupallforclonep3()
{
  ssh -i $KEY_PAIR root@${NODE[0]} "$GRID_ORACLE_HOME/crs/install/rootcrs.pl -deconfig -force -verbose;$GRID_ORACLE_HOME/root.sh -silent;ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat" > 1.log
}

setupallforclonep4()
{
  set -- $NODELIST
  NODECOUNT=1
  for i in $NODELIST ;
do
        if [ $NODECOUNT = 1 ] ; then
                echo "first node is finished"
        elif [ $NODECOUNT != $# ] ; then
                ssh -i $KEY_PAIR -f root@$i "$GRID_ORACLE_HOME/root.sh -silent;ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat" >> ${NODECOUNT}.log
                sleep 30
        else
                sleep 90
                ssh -i $KEY_PAIR root@$i "$GRID_ORACLE_HOME/root.sh -silent;ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat" >> ${NODECOUNT}.log
        fi
        NODECOUNT=`expr $NODECOUNT + 1`
done
}

setupall(){
  #startupinnstance
  setupnodelist
  sed -i "s/^NODELIST=.*/NODELIST=\"$NODELIST\"/" $0
  sed -i "s/^NODEids=.*/NODEids=\"$NODEids\"/" $0
  sed -i "s/^SERVER=.*/SERVER=\"$SERVER\"/" $0
  copyfile $0
  SERVER_AND_NODE="$SERVER $NODELIST"
  NODECOUNT=0
  for i in $SERVER_AND_NODE ;
  do
        ssh -i $KEY_PAIR -o "StrictHostKeyChecking no" root@$i "sh $0 setupnode $NODECOUNT"
        NODECOUNT=`expr $NODECOUNT + 1`
  done
  NODECOUNT=0
  for i in $SERVER_AND_NODE ;
  do
        ssh -i $KEY_PAIR -o "StrictHostKeyChecking no" root@$i "reboot"
        NODECOUNT=`expr $NODECOUNT + 1`
  done
  
}



case "$1" in
  "cleangridhome" ) cleangridhome;;
  "sshkeyscan" ) sshkeyscan;;
  "createclonebase" ) createclonebase;;
  "createsnapshot" ) createsnapshot $2 $3;;
  "listinstances" ) listinstances;;
  "listami" ) listami;;
  "createclonepl" ) createclonepl;;
  "createclusterlist" ) createclusterlist;;
  "createtmpl" ) createtmpl ;;
  "installpackage" ) installpackage ;;
  "changehostname" )  changehostname $2;;
  "createsshkey" ) createsshkey ;;
  "createuser" ) createuser ;;
  "changelocale" ) changelocale ;;
  "createoraclehome" ) createoraclehome ;;
  "setupdns" ) setupdns $2;;
  "setupnodelist" ) setupnodelist ;;
  "createtincconf" ) createtincconf $2;;
  "clone" ) clone $2;;
  "startinstances" ) startinstances $2 $3 $4 $5;;
  "requestspotinstances" ) requestspotinstances $2 $3 $4 $5;;
  "stopinstances" ) stopinstances ;;
  "terminateinstances" ) terminateinstances ;;
  "setupnodeforclone" ) setupnodeforclone $2;;
  "setupallforclonep1" ) setupallforclonep1 ;;
  "setupallforclonep2" ) setupallforclonep2 ;;
  "setupallforclonep3" ) setupallforclonep3 ;;
  "setupallforclonep4" ) setupallforclonep4 ;;
  "setupallforclonep5" ) setupallforclonep5 ;;
  "setupnode" ) setupnode $2;;
  "setupall" ) setupall ;;
  "setupkernel" ) setupkernel ;;
  "pretincconf" ) pretincconf ;;
  "createswap" ) createswap $2;;
  "setupiscsi" ) setupiscsi $2 $3;;
  * ) echo "known option or no option" ;;
esac
