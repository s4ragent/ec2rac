#/bin/bash
export LANG=C

LAUNCHGROUP="RACCLONE"
RACSnapshotId="snap-99a6676b"
PackageAmiId="ami-974234a7"
SWAP_DEVICE="/dev/xvdb:ephemeral0"
STORAGE_DEVICE="/dev/xvdb:ephemeral0"
ORACLE_HOME_DEVICE="/dev/xvdc:15:$RACSnapshotId"
WORK_DIR="/root/work"

#SWAP_SIZE=8
#RoleName,InstanceType,Instance-count,Price,amiid,device:size:snap-id,device:size:snap-id.....
Roles=(
"node m3.medium 2 0.05 $PackageAmiId $SWAP_DEVICE,$ORACLE_HOME_DEVICE"
"tinc m3.medium 1 0.05 $PackageAmiId"
"storage m3.medium 1 0.05 $PackageAmiId $STORAGE_DEVICE"
)

INSTALL_LANG=ja
TMPL_NAME="RACTMPL"
KEY_NAME="oregon"
KEY_PAIR="/root/work/${KEY_NAME}.pem"

RPMFORGE_URL="http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm"
EPEL_URL="http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm"

NETWORKS=("172.16.0.0" "172.17.0.0")
SUBNET_MASK="255.255.240.0"
NETWORK_NAME=("public" "priv")
SCAN_NAME="scan"
CLUSTER_NAME="node-cluster"
DBNAME="ORCL"
SIDNAME="ORCL" 
SYSPASSWORD="oracle123"
SYSTEMPASSWORD="oracle123"
REDOFILESIZE=500
DISKGROUPNAME="CRS"
FRA=$DISKGROUPNAME
ASMPASSWORD="oracle123"
CHARSET="AL32UTF8"
NCHAR="AL16UTF16"

TEMPLATENAME="General_Purpose.dbc"
DATABASETYPE="MULTIPURPOSE"


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
SSH_ARGS_APPEND="-i $KEY_PAIR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
export PDSH_SSH_ARGS_APPEND="$SSH_ARGS_APPEND -tt"
mac=`curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/ -s`
VpcId=`curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-id -s`
SubnetId=`curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/subnet-id -s`
Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
MyInstanceId=`curl -s http://169.254.169.254/latest/meta-data/instance-id`
MyIp=`ifconfig eth0 | grep 'inet addr' | awk -F '[: ]' '{print $13}'`
MyNetwork=`echo $MyIp | perl -ne ' if (/([\d]+\.[\d]+\.)/){ print $1}'`
MyNetwork="${MyNetwork}0.0"

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

#$1 RoleName $2 nodenumber
getnodename ()
{
  echo "$1"`printf "%.3d" $2`
}

getsgname()
{
	SgName="${1}-${LAUNCHGROUP}-${VpcId}"
	echo $SgName
}

getsgid()
{
	SgId=`aws ec2 describe-security-groups --region $Region --group-names $1 --query 'SecurityGroups[].GroupId' --output text`
	echo $SgId
}

setnodelist()
{
  mkdir -p $WORK_DIR
  rm -rf $WORK_DIR/*.id
  rm -rf $WORK_DIR/*.ip
  cat /dev/null >$WORK_DIR/all.id
  cat /dev/null >$WORK_DIR/all.ip
  for Role in "${Roles[@]}"
  do
        PARAMS=($Role)
        
	SgName=`getsgname ${PARAMS[0]}`
	SgId=`getsgid $SgName`
	  
	NODEOBJ=`aws ec2 describe-instances --region $Region --filter "Name=instance.group-id,Values=$SgId" --query 'Reservations[].Instances[].[InstanceId,[NetworkInterfaces[].PrivateIpAddress]]' --output text`
	NODEOBJ=`echo $NODEOBJ`
	
	  
  	cat /dev/null >$WORK_DIR/${PARAMS[0]}.id
  	cat /dev/null >$WORK_DIR/${PARAMS[0]}.ip
	CNT=0
	for i in $NODEOBJ ;
	do
	      	if [ `expr $CNT % 2` == 0 ]; then
	      		echo $i >> $WORK_DIR/${PARAMS[0]}.id
	      		echo $i >> $WORK_DIR/all.id
	      	else
	        	echo $i >> $WORK_DIR/${PARAMS[0]}.ip
	        	echo $i >> $WORK_DIR/all.ip
	      	fi
	      	CNT=`expr $CNT + 1`
	done

  done
}

#$1 nodetype(ex node/tinc/storage" $2 ip or id
getnodelist()
{
	echo `cat $WORK_DIR/${1}.${2}`
}

getmynumber()
{
	LIST=`getnodelist $1 id`
	CNT=1
	for i in $LIST ;
	do
	      	if [ $i == $MyInstanceId ]; then
	      		echo $CNT
	      	fi
	      	CNT=`expr $CNT + 1`
	done
	
}

getmyrole()
{
	MyRole="unknown"
	for Role in "${Roles[@]}"
	do
        	PARAMS=($Role)
        	RoleName=${PARAMS[0]}
        	LIST=`getnodelist $RoleName id`
		for i in $LIST ;
  		do
        		if [ "$i" == "$MyInstanceId" ] ; then
                		MyRole=$RoleName
        		fi
  		done
  	done
  	echo $MyRole
}

getmyname()
{
	MyRole=`getmyrole`
	MyNumber=`getmynumber $MyRole`
	echo `getnodename $MyRole $MyNumber`
}

#
createclonepl()
{
	Role=`getmyrole`
  $NODELIST=`getnodelist $Role ip`
  CLUSTER_NODES="{"
  NODECOUNT=1
  for i in $NODELIST ;
  do
        HOSTNAME=`getnodename $Role $NODECOUNT`
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

#$1 device
createswap(){
	FIRST_IFS=$IFS
        local IFS=','
        for device in ${SWAP_DEVICE}
        do
            SECOND_IFS=$IFS
            local IFS=':'
            local args=($device)
            
            mount -f ${args[0]};mkswap -f ${args[0]};swapon ${args[0]}
            sed -i 's/\(.*cloudconfig\)/#\1/' /etc/fstab
            echo "${args[0]} swap swap defaults 0 0 " >> /etc/fstab
       
            local IFS=$SECOND_IFS
        done
        local IFS=$FIRST_IFS
}

#1　Storage_device
createtgtd()
{
	FIRST_IFS=$IFS
        local IFS=','
        local CNT=0
        for device in ${STORAGE_DEVICE}
        do
            SECOND_IFS=$IFS
            local IFS=':'
            local args=($device)
            mddevice="$mddevice ${args[0]}"
       
            local IFS=$SECOND_IFS
            CNT=`expr $CNT + 1`
        done
        local IFS=$FIRST_IFS
        if [ $CNT != 1 ] ; then
                mdadm --create /dev/md0 --level=0 --raid-devices=$CNT $mddevice
                mdadm --detail --scan >> /etc/mdadm/mdadm.conf
                DEVICE=/dev/md0
        else
        	DEVICE=$mddevice
        fi
      
    	umount -f ${DEVICE}
    	sfdisk -uM ${DEVICE} <<EOF
,,83
EOF
    	sleep 15
    	cat > /etc/tgt/targets.conf <<EOF
<target ${SCSI_TARGET_NAME}>
# List of files to export as LUNs
        <backing-store ${DEVICE}1>
                lun 1
        </backing-store>
initiator-address ALL
</target>
EOF

	sed -i 's/\(.*cloudconfig\)/#\1/' /etc/fstab
	/etc/init.d/tgtd start
	chkconfig tgtd on
	tgt-admin --show	
}

setupiscsi(){
	Role=`getmyrole`
	TARGETIP=`getnodelist storage ip`
	MYNUMBER=`getmynumber $Role`
        /etc/init.d/iscsi start
        iscsiadm --mode discovery --type sendtargets -p ${TARGETIP}
        iscsiadm --mode node --targetname ${SCSI_TARGET_NAME} --login
        chkconfig iscsi on
        /etc/init.d/iscsi restart
        sleep 15
        echo 'KERNEL=="sd[a-d]*",ACTION=="add|change",OWNER="grid",GROUP="asmadmin",MODE="0660"' > /etc/udev/rules.d/99-oracle.rules
        #initialize asmdisk if nodenumber=1 ####        
        if [ $MYNUMBER = 1 ]; then     
                sfdisk /dev/sda << EOF
,,83
EOF
                dd if=/dev/zero of=/dev/sda1 bs=1M count=100
        fi
}





installpackage ()
{
  rpm -ivh $RPMFORGE_URL
  rpm -ivh $EPEL_URL
  yum -y groupinstall "Desktop" "X Window System" "Japanese Support"
  yum -y install pdsh unzip oracle-rdbms-server-12cR1-preinstall tigervnc-server screen nfs-utils dnsmasq scsi-target-utils iscsi-initiator-utils firefox.x86_64 xrdp expect tinc patch
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






clone()
{
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
  aws ec2 describe-instances --region $Region --query 'Reservations[].Instances[].[InstanceId,NetworkInterfaces[]."PrivateIpAddress"]' --output text
}

listami()
{
  aws ec2 describe-images --region $Region --owner self --query 'Images[].[Name,ImageId]' --output text
}



createsecuritygroup(){
  SgName=`getsgname ${1} ${VpcId}`
  SgId=`getsgid $SgName $Region`

  if [ "$SgId" != "" ] ; then
 	aws ec2 delete-security-group --group-id $SgId --region $Region > /dev/null
  fi
  SgId=`aws ec2 create-security-group --group-name $SgName --description "$SgName"  --vpc-id $VpcId --region $Region --query 'GroupId' --output text`
  aws ec2 authorize-security-group-ingress --group-id $SgId --cidr $MyNetwork/16 --protocol -1 --port -1 --region $Region > /dev/null


  echo $SgId

}



requestspotinstances(){
  for Role in "${Roles[@]}"
  do
        SgId=`createsecuritygroup ${Role}`
        DeviceJson=`createdevicejson ${Role}`
        PARAMS=($Role)
        if [ "$DeviceJson" != "" ]; then
        	Json={\"ImageId\":\"${PARAMS[4]}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${PARAMS[1]}\",\"BlockDeviceMappings\":$DeviceJson,\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"${SgId}\"]}
        else
        	Json={\"ImageId\":\"${PARAMS[4]}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${PARAMS[1]}\",\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"${SgId}\"]}
        fi
        
        aws ec2 request-spot-instances --spot-price ${PARAMS[3]} --region $Region --launch-group $LAUNCHGROUP --launch-specification $Json --instance-count ${PARAMS[2]} 
  done
	
}

createdevicejson()
{
	#NodedeviceJson=\"BlockDeviceMappings\":[{\"DeviceName\":\"$ORACLE_HOME_DEVICE\",\"Ebs\":{\"VolumeSize\":$ORACLE_HOME_SIZE,\"SnapshotId\":\"$RACSnapshotId\",\"DeleteOnTermination\":true,\"VolumeType\":\"standard\"}},{\"DeviceName\":\"$SWAP_DEVICE\",\"VirtualName\":\"ephemeral0\"}]
  devicelist=$6
  if [ "$devicelist" != "" ]; then
        #$6=device:size:snap-id,device:size:snap-id
        DeviceJson="["
        FIRST_IFS=$IFS
        local IFS=','
        local CNT=1
        
        for device in $devicelist
        do
            SECOND_IFS=$IFS
            local IFS=':'
            local args=($device)
                
            if [ $CNT != 1 ]; then
            	DeviceJson="$DeviceJson,"
            fi

            if [ ! -z `echo ${args[1]} | grep "ephemeral"` ]; then
               #ephemeral"
               DeviceJson=$DeviceJson{\"DeviceName\":\"${args[0]}\",\"VirtualName\":\"${args[1]}\"}
            else
            	if [ "${args[2]}" != "" ]; then
               		DeviceJson=$DeviceJson{\"DeviceName\":\"${args[0]}\",\"Ebs\":{\"VolumeSize\":${args[1]},\"SnapshotId\":\"${args[2]}\",\"DeleteOnTermination\":true,\"VolumeType\":\"gp2\"}}        	
            	else
            		DeviceJson=$DeviceJson{\"DeviceName\":\"${args[0]}\",\"Ebs\":{\"VolumeSize\":${args[1]},\"DeleteOnTermination\":true,\"VolumeType\":\"gp2\"}}
            	fi
            fi

            local IFS=$SECOND_IFS
            CNT=`expr $CNT + 1`
        done
        local IFS=$FIRST_IFS
        DeviceJson="$DeviceJson]"
        echo $DeviceJson
   else
   	echo ""
   fi
}

startinstances(){
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
  instanceIds=`getnodelist all id`
  aws ec2 stop-instances --region $Region --instance-ids $instanceIds 
}

terminate()
{
  setnodelist
  instanceIds=`getnodelist all id`
  aws ec2 terminate-instances --region $Region --instance-ids $instanceIds
  SpotInstanceRequestIds=`aws ec2 describe-spot-instance-requests --region $Region --filters "Name=launch-group,Values=$LAUNCHGROUP" --query 'SpotInstanceRequests[].SpotInstanceRequestId' --output text`
  SpotInstanceRequestIds=`echo $SpotInstanceRequestIds`
  aws ec2 cancel-spot-instance-requests --region $Region --spot-instance-request-ids $SpotInstanceRequestIds
  requestcount=`aws ec2 describe-spot-instance-requests --region $Region --filters "Name=launch-group,Values=$LAUNCHGROUP"  --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
  while [ $requestcount != 0 ]
  do
    sleep 10
    requestcount=`aws ec2 describe-spot-instance-requests --region $Region --filters "Name=launch-group,Values=$LAUNCHGROUP"  --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
  done
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

setdhcp()
{
	SERVER=`getnodelist storage ip`
	echo "supersede domain-name-servers ${SERVER};" >> /etc/dhcp/dhclient-eth0.conf
}

setupdns ()
{

    echo "### scan entry ###" >> /etc/hosts
    getip 0 scan >> /etc/hosts
    echo "### public,vip entry###" >> /etc/hosts
    
    ALLCOUNT=1
    for Role in "${Roles[@]}"
    do
        	PARAMS=($Role)
        	RoleName=${PARAMS[0]}
        	LIST=`getnodelist RoleName ip`
        	NODECOUNT=1
		for i in $LIST ;
		do
			echo "`getip 0 real $ALLCOUNT` `getnodename $RoleName $NODECOUNT`.${NETWORK_NAME[0]} `getnodename $RoleName $NODECOUNT`" >> /etc/hosts
			echo "`getip 0 vip $ALLCOUNT` `getnodename $RoleName $NODECOUNT`-vip.${NETWORK_NAME[0]} `getnodename $RoleName $NODECOUNT`-vip" >> /etc/hosts
			NODECOUNT=`expr $NODECOUNT + 1`
			ALLCOUNT=`expr $ALLCOUNT + 1`
		done
    done

    ###enable dnsmasq####
    chkconfig dnsmasq on
    /etc/init.d/dnsmasq start


}


pretincconf()
{
  rm -rf $WORK_DIR/hosts
  mkdir -p $WORK_DIR/hosts
  cat > $WORK_DIR/tinc.conf <<EOF
Name = dummy
Interface = tap0
Mode = switch
BindToAddress * 655
MaxTimeout = 30

EOF
  cat > $WORK_DIR/hosts/dummy<<EOF
Address = 127.0.0.1 655
Cipher = none
Digest = none
EOF
  expect -c "
spawn tincd --config $WORK_DIR -K
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
	myRole=`getmyrole`
	myNumber=`getmynumber all`
	rm -rf /var/run/tinc.*
	/etc/init.d/tinc stop
	sleep 5
	rm -rf /etc/tinc
	NODENAME=`getmyname`
	for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
	do
    		NETNAME=${NETWORK_NAME[$k]}
    		
    		echo $NETNAME >> /etc/tinc/nets.boot
    		echo "tinc          ${PORT}/tcp             #TINC" >> /etc/services
    		echo "tinc          ${PORT}/udp             #TINC" >> /etc/services
    		cp $WORK_DIR/tinc.conf /etc/tinc/$NETNAME/tinc.conf
    		sed -i "s/^Name =.*/Name = $NODENAME/" /etc/tinc/$NETNAME/tinc.conf
    		sed -i "s/^Interface = .*/Interface = tap${k}/" /etc/tinc/$NETNAME/tinc.conf
    		sed -i "s/^BindToAddress.*/BindToAddress \* $PORT/" /etc/tinc/$NETNAME/tinc.conf
    		cp $WORK_DIR/rsa_key.priv /etc/tinc/$NETNAME/rsa_key.priv
    		
    		##create ifconfig file
    		IP=`getip $k real $myNumber`
		echo '#!/bin/sh' > /etc/tinc/$NETNAME/tinc-up
		echo "ifconfig \$INTERFACE ${IP} netmask $SUBNET_MASK" >> /etc/tinc/$NETNAME/tinc-up
		chmod 755 /etc/tinc/$NETNAME/tinc-up
		
		echo '#!/bin/sh' > /etc/tinc/$NETNAME/tinc-down
		echo "ifconfig \$INTERFACE down" >> /etc/tinc/$NETNAME/tinc-down
		chmod 755 /etc/tinc/$NETNAME/tinc-down

		##create hostsfile
    		mkdir -p /etc/tinc/$NETNAME/hosts
		for Role in "${Roles[@]}"
  		do
        		PARAMS=($Role)
        		RoleName=${PARAMS[0]}
        		LIST=`getnodelist RoleName ip`
        		NODECOUNT=1
			for i in $LIST ;
			do
				NODENAME=`getnodename $RoleName $NODECOUNT`
				cp $WORK_DIR/hosts/dummy /etc/tinc/$NETNAME/hosts/$NODENAME
				sed -i "s/^Address = .*/Address = $i $PORT/" /etc/tinc/$NETNAME/hosts/$NODENAME
				NODECOUNT=`expr $NODECOUNT + 1`
			done
    		done
    		
    		##create connect to###
    		
    		if [ "$myRole" = "tinc" ] ; then
    			LIST=`getnodelist tinc ip`
			NODECOUNT=1
			for i in $LIST ;
			do
				NODENAME=`getnodename tinc $NODECOUNT`
				echo "ConnectTo = $NODENAME" >> /etc/tinc/$NETNAME/tinc.conf
				NODECOUNT=`expr $NODECOUNT + 1`
			done
		else
			LIST=(`getnodelist tinc ip`)
			NODECOUNT=`expr $myNumber % ${#LIST[@]}`
			NODECOUNT=`expr $NODECOUNT + 1`
			NODENAME=`getnodename tinc $NODECOUNT`
			echo "ConnectTo = $NODENAME" >> /etc/tinc/$NETNAME/tinc.conf
		fi
    		
		
		PORT=`expr $PORT + 1`
	done
	chkconfig tinc on
	/etc/init.d/tinc start

	count=`grep checktinc /etc/rc.d/rc.local | wc -l`
	if [ $count = 0 ] ; then
		echo "sh `pwd`/$0 checktinc" >> /etc/rc.d/rc.local
	fi

}

checktinc(){
  multi=1
  for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
  do
    tcount=`ifconfig | grep tap${k} | wc -l`
    multi=`expr $tcount \* $multi`
  done

  if [ $multi = 0 ] ; then
    createtincconf
  fi

}


creatersp()
{
  myRole=`getmyrole`
  myNumber=`getmynumber $myRole`
  if [ $myNumber = 1 ] ; then

    NODECOUNT=1
    NODELIST=`getnodelist $myRole ip`
    for i in $NODELIST ;
    do
      NODENAME=`getnodename $myRole $NODECOUNT`
      if [ $NODECOUNT = 1 ] ; then
        CLUSTERNODES="${NODENAME}:${NODENAME}-vip"
      else
        CLUSTERNODES="$CLUSTERNODES,${NODENAME}:${NODENAME}-vip"
      fi
    
      NODECOUNT=`expr $NODECOUNT + 1`
    done
    
  cat > /home/grid/asm.rsp <<EOF
oracle.assistants.asm|S_ASMPASSWORD=$ASMPASSWORD
oracle.assistants.asm|S_ASMMONITORPASSWORD=$ASMPASSWORD
EOF
  cat > /home/grid/grid.rsp  <<EOF
oracle.install.responseFileVersion=/oracle/install/rspfmt_crsinstall_response_schema_v12.1.0
ORACLE_HOSTNAME=`hostname`
INVENTORY_LOCATION=$ORAINVENTORY
SELECTED_LANGUAGES=en,ja
oracle.install.option=CRS_CONFIG
ORACLE_BASE=$GRID_ORACLE_BASE
ORACLE_HOME=$GRID_ORACLE_HOME
oracle.install.asm.OSDBA=asmdba
oracle.install.asm.OSOPER=asmoper
oracle.install.asm.OSASM=asmadmin
oracle.install.crs.config.gpnp.scanName=${SCAN_NAME}.${NETWORK_NAME[0]}
oracle.install.crs.config.gpnp.scanPort=1521
oracle.install.crs.config.ClusterType=STANDARD
oracle.install.crs.config.clusterName=$CLUSTER_NAME
oracle.install.crs.config.gpnp.configureGNS=false
oracle.install.crs.config.autoConfigureClusterNodeVIP=false
oracle.install.crs.config.gpnp.gnsOption=CREATE_NEW_GNS
oracle.install.crs.config.gpnp.gnsClientDataFile=
oracle.install.crs.config.gpnp.gnsSubDomain=
oracle.install.crs.config.gpnp.gnsVIPAddress=
oracle.install.crs.config.clusterNodes=$CLUSTERNODES
oracle.install.crs.config.networkInterfaceList=eth0:$MyNetwork:3,tap0:${NETWORKS[0]}:1,tap1:${NETWORKS[1]}:2
oracle.install.crs.managementdb.configure=false
oracle.install.crs.config.storageOption=LOCAL_ASM_STORAGE
oracle.install.crs.config.sharedFileSystemStorage.votingDiskLocations=
oracle.install.crs.config.sharedFileSystemStorage.votingDiskRedundancy=NORMAL
oracle.install.crs.config.sharedFileSystemStorage.ocrLocations=
oracle.install.crs.config.sharedFileSystemStorage.ocrRedundancy=NORMAL
               	
oracle.install.crs.config.useIPMI=false
oracle.install.crs.config.ipmi.bmcUsername=
oracle.install.crs.config.ipmi.bmcPassword=
oracle.install.asm.SYSASMPassword=$ASMPASSWORD
oracle.install.asm.diskGroup.name=$DISKGROUPNAME
oracle.install.asm.diskGroup.redundancy=EXTERNAL
oracle.install.asm.diskGroup.AUSize=1
oracle.install.asm.diskGroup.disks=/dev/sda1
oracle.install.asm.diskGroup.diskDiscoveryString=
oracle.install.asm.monitorPassword=$ASMPASSWORD
oracle.install.crs.config.ignoreDownNodes=false
oracle.installer.autoupdates.option=
oracle.installer.autoupdates.downloadUpdatesLoc=
AUTOUPDATES_MYORACLESUPPORT_USERNAME=
AUTOUPDATES_MYORACLESUPPORT_PASSWORD=
PROXY_HOST=
PROXY_PORT=0
PROXY_USER=
PROXY_PWD=
PROXY_REALM=
[ConfigWizard]
oracle.install.asm.useExistingDiskGroup=false
[ConfigWizard]
EOF

  cat >> /home/grid/asmused.sql <<'EOF'
select group_number, name, total_mb, free_mb,total_mb - free_mb
from v$asm_diskgroup;
exit;
EOF
    chmod 777 /home/grid/grid.rsp
    chmod 777 /home/grid/asm.rsp
    chmod 777 /home/grid/asmused.sql
  fi

}


changehostname ()
{
  HOSTNAME=`getmyname`
  sed -i 's/hostname/#hostname/' /etc/rc.local
  cat > /etc/sysconfig/network <<EOF
NETWORKING=yes
NETWORKING_IPV6=no
HOSTNAME=${HOSTNAME}.${NETWORK_NAME[0]}
EOF
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
        cat /root/.ssh/authorized_keys >> /home/$user/.ssh/authorized_keys
        cp $KEY_PAIR /home/$user/.ssh/id_rsa
        cat >> /home/$user/.ssh/ <<'EOF'
host *        
StrictHostKeyChecking no
UserKnownHostsFile=/dev/null
EOF
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
    sfdisk -uM ${ORACLE_HOME_DEVICE} <<EOF
,,83
EOF
    sleep 15
    mkfs.ext3 -F ${ORACLE_HOME_DEVICE}1
}

mountoraclehome()
{
    echo "${ORACLE_HOME_DEVICE}1               ${MOUNT_PATH}                    ext3    defaults        0 0" >> /etc/fstab
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

  MyIp=`ifconfig eth0 | grep 'inet addr' | awk -F '[: ]' '{print $13}'`
  SERVER_AND_NODE="$SERVER $NODELIST"
  NODECOUNT=0
  for i in $SERVER_AND_NODE ;
  do
    if [ "$i" = "$MyIp" ] ; then
      MyNumber=$NODECOUNT
      break
    fi
    NODECOUNT=`expr $NODECOUNT + 1`
  done
  
  changelocale
  chkconfig xrdp on
  changehostname $MyNumber
  setupdns $MyNumber
  createtincconf $MyNumber
  createswap $MyNumber
  setupiscsi $MyNumber
  mountoraclehome $MyNumber
  cleangridhome
  createclonepl
  creatersp $MyNumber
  watch
}


cleangridhome()
{
  OLD_IFS=$IFS
  local IFS='/'
  set -- $GRID_ORACLE_HOME
  local IFS=$OLD_IFS
  for i in "$@"
  do
    if [ "$i" != "" ] ; then
        CHMODPATH=${CHMODPATH}"/"${i}
        chown grid:oinstall $CHMODPATH
    fi
  done
  rm -rf $ORAINVENTORY
  mkdir -p $ORAINVENTORY
  chown grid:oinstall $ORAINVENTORY
  chown grid:oinstall $GRID_ORACLE_BASE
  chown -R grid:oinstall $GRID_ORACLE_HOME
  #chmod u+s $GRID_ORACLE_HOME/bin/oracle
  #chmod g+s $GRID_ORACLE_HOME/bin/oracle
  #chmod u+s $GRID_ORACLE_HOME/bin/extjob
  #chmod u+s $GRID_ORACLE_HOME/bin/jssu
  #chmod u+s $GRID_ORACLE_HOME/bin/oradism
  
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

setupnode()
{
  changelocale
  chkconfig xrdp on
  changehostname $1
  setupdns $1
  createtincconf $1
  createswap $1
  setupiscsi $1
  fdiskoraclehome $1
  mountoraclehome $1
  createoraclehome
}

test(){
	#requestspotinstances
	#instancecount=0
	#for Role in "${Roles[@]}"
	
	#do
	#	PARAMS=($Role)
	#	instancecount=`expr $instancecount + $PARAMS[2]`
	#done
	
	#requestcount=`aws ec2 describe-spot-instance-requests --region $Region --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
	#while [ $instancecount != $requestcount ]
	#do
	#	sleep 10
 	#	requestcount=`aws ec2 describe-spot-instance-requests --region $Region --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
	#done
	#setnodelist
	
	
	CMD="pdsh -R ssh -t 10 -w ^$WORK_DIR/all.ip -S hostname"
	$CMD
	RET=$?
	while [ $RET != 0 ]
	do
		sleep 10
		$CMD
		RET=$?
	done
	
	copyfile all work
}
dsh()
{
	pdsh -R ssh -w ^$WORK_DIR/$1.ip $2 $3 $4 $5 $6
}

setupallforclone(){
  MEMORYTARGET=$5
  PARALLEL=$6
  export PDSH_SSH_ARGS_APPEND=$PDSH_SSH_ARGS_APPEND
  
  curtime=`date +"%Y-%m%d-%H%M"`
  Master_dir="./logs/${curtime}"
  mkdir -p $Master_dir
  echo "$1_$2_$3_$4_$5_$6" > $Master_dir/main.log
  echo "start of clone `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  echo "start of request spot instance startup  `date`" >> $Master_dir/main.log
  Region=`curl http://169.254.169.254/latest/meta-data/placement/availability-zone -s | perl -pe chop`
  #server-instance-type sever-count node-instance-type node-count
  requestspotinstances $1 $2 $3 $4
  instancecount=`expr $2 + $4`
  requestcount=`aws ec2 describe-spot-instance-requests --region $Region --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
  while [ $instancecount != $requestcount ]
  do
    sleep 10
    requestcount=`aws ec2 describe-spot-instance-requests --region $Region --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
  done
  echo "end of request(request is fulfilled)  `date`" >> $Master_dir/main.log
  
  setupnodelist
  sed -i "s/^NODELIST=.*/NODELIST=\"$NODELIST\"/" $0
  sed -i "s/^NODEids=.*/NODEids=\"$NODEids\"/" $0
  sed -i "s/^SERVER=.*/SERVER=\"$SERVER\"/" $0
  
  #create hosts file
  echo "127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 `hostname -s`" >/etc/hosts
  echo "::1         localhost localhost.localdomain localhost6 localhost6.localdomain6" >> /etc/hosts
  
  NODECOUNT=0
  SERVER_AND_NODE="$SERVER $NODELIST"
  cat "" > ./hostlist 
  for i in $SERVER_AND_NODE ;
  do
    echo `getnodename $NODECOUNT` >> ./hostlist
    echo "$i `getnodename $NODECOUNT`" >> /etc/hosts
    NODECOUNT=`expr $NODECOUNT + 1`
  done  
  
  #check server_and_node is alive
  CMD="pdsh -R ssh -t 10 -w ^hostlist -S date"
  $CMD
  RET=$?
  while [ $RET != 0 ]
  do
    sleep 10
    $CMD
    RET=$?
  done
  
  copyfile $0
  
  
  echo "end of request spot instance startup and copyfile `date`" >> $Master_dir/main.log 

  echo "*********************" >> $Master_dir/main.log
  echo "start of server dns&iscsi  `date`" >> $Master_dir/main.log
  ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 0` "sleep 10;sh -x $0 setupnodeforclone;reboot" > $Master_dir/dns_iscsi.log

  #prevent connect before reboot
  sleep 60
  CMD="ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 0` date"
  $CMD
  RET=$?
  while [ $RET != 0 ]
  do
    sleep 10
    $CMD
    RET=$?
  done
  
  echo "end of server dns&iscsi  `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  
  echo "start of node dns&iscsi  `date`" >> $Master.log
  echo "start of node dns&iscsi  `date`"
  pdsh -R ssh -f 200 -w ^hostlist -x `getnodename 0` "hostname;date;sh -x $0 setupnodeforclone;date" | dshbak >>$Master_dir/dns_iscsi.log
  pdsh -R ssh -f 200 -u 120 -w ^hostlist -x `getnodename 0` reboot
  sleep 120
  #check node is alive
  CMD="pdsh -R ssh -f 200 -w ^hostlist -x `getnodename 0` -S date"
  $CMD
  RET=$?
  while [ $RET != 0 ]
  do
    sleep 10
    $CMD
    RET=$?
  done
  
  sleep 10
  echo "end of node dns&iscsi  `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  echo "start of grid software install  `date`" >> $Master_dir/main.log
  echo "start of grid software install  `date`" >> $Master_dir/grid_install.log
  pdsh -R ssh -f 200 -w ^hostlist -x `getnodename 0` "hostname;date;sudo -u grid /home/grid/start.sh;$ORAINVENTORY/orainstRoot.sh" | dshbak >> $Master_dir/grid_install.log
  
  echo "end of grid software install  `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  
  echo "start of config.sh `date`" >> $Master_dir/main.log
  echo "start of config.sh `date`" >> $Master_dir/config_sh.log
  ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 1` "sudo -u grid $GRID_ORACLE_HOME/crs/config/config.sh -silent -responseFile /home/grid/grid.rsp" >> $Master_dir/config_sh.log
  echo "end of config.sh `date`" >> $Master_dir/main.log
  

  
  echo "start of first node of root.sh `date`" >>  $Master_dir/main.log
  ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 1` "sh $0 exerootsh" >> $Master_dir/failhost
  echo "end of first node of root.sh `date`" >> $Master_dir/main.log
  echo "start of second node to last node of root.sh `date`" >> $Master_dir/main.log
  pdsh -R ssh -f $PARALLEL -w ^hostlist -x `getnodename 0`,`getnodename 1` "sh $0 exerootsh"  >> $Master_dir/failhost
  echo "end of second node to last node of root.sh `date`" >> $Master_dir/main.log
  
  echo "start of first node of configToolAllCommands `date`" >> $Master_dir/main.log
  ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 1`  "sudo -u grid $GRID_ORACLE_HOME/cfgtoollogs/configToolAllCommands RESPONSE_FILE=/home/grid/asm.rsp" >> $Master_dir/config_sh.log
  echo "*********************" >> $Master_dir/main.log
  echo "start of oracle install  `date`" >>$Master_dir/main.log
  pdsh -R ssh -f 200 -w ^hostlist -x `getnodename 0`  "hostname;date;sudo -u oracle /home/oracle/start.sh;$ORA_ORACLE_HOME/root.sh -silent" | dshbak >> $Master_dir/oracle_install.log
  echo "end of oracle install  `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  echo "start of dbca `date`" >> $Master_dir/main.log

  dbcaoption="-silent -createDatabase -templateName $TEMPLATENAME -gdbName $DBNAME -sid $SIDNAME" 
  dbcaoption="$dbcaoption -SysPassword $SYSPASSWORD -SystemPassword $SYSTEMPASSWORD -emConfiguration NONE -redoLogFileSize $REDOFILESIZE"
  dbcaoption="$dbcaoption -recoveryAreaDestination $FRA -storageType ASM -asmSysPassword $ASMPASSWORD -diskGroupName $DISKGROUPNAME"
  dbcaoption="$dbcaoption -characterSet $CHARSET -nationalCharacterSet $NCHAR -totalMemory $MEMORYTARGET -databaseType $DATABASETYPE"

  NODECOUNT=1
  for i in $NODELIST ;
  do
    if [ $NODECOUNT = 1 ] ; then
      dbcaoption="$dbcaoption -nodelist `getnodename $NODECOUNT`"
    else
      dbcaoption="$dbcaoption,`getnodename $NODECOUNT`"
    fi
    NODECOUNT=`expr $NODECOUNT + 1`
  done

  ssh $PDSH_SSH_ARGS_APPEND root@`getnodename 1`  "sudo -u oracle $ORA_ORACLE_HOME/bin/dbca $dbcaoption"  >> $Master_dir/dbca.log

  echo "end of dbca `date`" >> $Master_dir/main.log
  echo "*********************" >> $Master_dir/main.log
  echo "end of clone `date`" >> $Master_dir/main.log
  
  echo "result `date`" >> $Master_dir/main.log
  ssh -i ./id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null grid@`getnodename 1` 'source .bash_profile;export ORACLE_SID=+ASM1;sqlplus "/as sysdba" @asmused.sql;crsctl status resource -t' >> $Master_dir/main.log
  
  pdsh -R ssh -f 200 -w ^hostlist "hostname;date;sar -u;sar -b" | dshbak >> $Master_dir/sar.log
  getlogs $Master_dir
  
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


exessh()
{
  LIST=(`getnodelist node ip`)
  ssh $SSH_ARGS_APPEND root@${LIST[$1]} $2 $3 $4 $5 $6
}

catrootsh()
{
  exessh $1 "ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat"
}

updatescript()
{
  curl https://raw.githubusercontent.com/s4ragent/ec2rac/master/${0}?id=${RANDOM} -o ${0}
}

copyfile()
{
  LIST=`getnodelist $1 ip`
  for i in $LIST ;
  do
    scp $SSH_ARGS_APPEND -r $2 root@$i:/root/
  done
}


#$1 RoleName $2 remotedir(getdir) $3 localdir
getfile()
{
  LIST=`getnodelist $1 ip`
  NODECOUNT=1
  for i in $LIST ;
  do
  	localdir=$3/`getnodename $1 $NODECOUNT`/$2
        mkdir $localdir
        scp $SSH_ARGS_APPEND -r root@$i:$2 $localdir
        NODECOUNT=`expr $NODECOUNT + 1`
  done
}

getlogs()
{
  getfile /root/watch $1
  getfile $GRID_ORACLE_HOME/log $1
  getfile $GRID_ORACLE_HOME/install/root* $1
  getfile /var/log/tinc.log $1
  getfile $ORAINVENTORY/logs $1
}

exerootsh()
{
  $GRID_ORACLE_HOME/crs/install/rootcrs.pl -deconfig -force -verbose >& /dev/null
  $GRID_ORACLE_HOME/root.sh -silent >& /dev/null
  RET=$?
  if [ $RET != 0 ] ; then
	echo `hostname -s`
  fi
}

case "$1" in
  "exerootsh" ) exerootsh;;
  "getlogs" ) getlogs $2 $3;;
  "getfile" ) getfile $2 $3;;
  "watch" ) watch;;
  "cleangridhome" ) cleangridhome;;
  "createclonebase" ) createclonebase;;
  "createsnapshot" ) createsnapshot $2 $3;;
  "listinstances" ) listinstances;;
  "listami" ) listami;;
  "createclonepl" ) createclonepl;;
  "creatersp" ) creatersp $2;;
  "createtmpl" ) createtmpl ;;
  "installpackage" ) installpackage ;;
  "changehostname" )  changehostname $2;;
  "createsshkey" ) createsshkey ;;
  "createuser" ) createuser ;;
  "changelocale" ) changelocale ;;
  "createoraclehome" ) createoraclehome ;;
  "setupdns" ) setupdns $2;;
  "setnodelist" ) setnodelist;;
  "getnodelist" ) getnodelist $2 $3;;
  "createtincconf" ) createtincconf $2;;
  "clone" ) clone $2;;
  "startinstances" ) startinstances $2 $3;;
  "requestspotinstances" ) requestspotinstances $2 $3 $4 $5;;
  "stopinstances" ) stopinstances ;;
  "terminate" ) terminate ;;
  "setupnodeforclone" ) setupnodeforclone $2;;
  "setupallforclone" ) setupallforclone $2 $3 $4 $5 $6 $7;;
  "setupnode" ) setupnode $2;;
  "setupall" ) setupall ;;
  "setupkernel" ) setupkernel ;;
  "pretincconf" ) pretincconf ;;
  "createswap" ) createswap $2;;
  "setupiscsi" ) setupiscsi $2 $3;;
  "exessh" ) exessh $2 $3 $4 $5 $6;;
  "catrootsh" ) catrootsh $2;;
  "updatescript" ) updatescript;;
  "checktinc" ) checktinc $2;;
  "createdevicejson" ) createdevicejson $2;;
  "test" ) test;;
  "copyfile" ) copyfile $2 $3;;
  "dsh" ) dsh $2 $3 $4 $5 $6;;
  * ) echo "Ex \"sh -x $0 setupallforclone c1.xlarge 1 m3.medium 10 2400 0\" 2400 means memorytarget, 0 means wait 0 seconds when grid root.sh" ;;
esac
