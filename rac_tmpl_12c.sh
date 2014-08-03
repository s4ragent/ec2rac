#!/bin/bash
export LANG=C

LAUNCHGROUP="RACCLONE"
RACSnapshotId="snap-99a6676b"
PackageAmiId="ami-3fa7dc0f"
SWAP_DEVICE="/dev/xvdb:ephemeral0"
STORAGE_DEVICE="/dev/xvdb:ephemeral0"
HOME_DEVICE="/dev/sda1:15"
ORACLE_HOME_DEVICE="/dev/xvdc:15:$RACSnapshotId"
WORK_DIR="/root/work"

#SWAP_SIZE=8
#RoleName,InstanceType,Instance-count,Price,amiid,device:size:snap-id,device:size:snap-id.....
Roles=(
"node m3.large 40 0.05 $PackageAmiId $HOME_DEVICE,$SWAP_DEVICE,$ORACLE_HOME_DEVICE"
"tinc c3.large 2 0.05 $PackageAmiId $HOME_DEVICE"
"storage m1.large 1 0.05 $PackageAmiId $HOME_DEVICE,$STORAGE_DEVICE"
)

PARALLEL=5
MAXREQUESTWAIT=1200
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
REDOFILESIZE=10
DISKGROUPNAME="CRS"
FRA=$DISKGROUPNAME
ASMPASSWORD="oracle123"
CHARSET="AL32UTF8"
NCHAR="AL16UTF16"
MEMORYTARGET=4800
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
SCP_ARGS_APPEND="-i $KEY_PAIR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_ARGS_APPEND="$SCP_ARGS_APPEND -tt"
export PDSH_SSH_ARGS_APPEND="$SSH_ARGS_APPEND"
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

getnodeip()
{
	LIST=(`getnodelist $1 ip`)
	hostnumber=`expr $2 - 1`
	echo ${LIST[$hostnumber]}
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
	  
	NODEOBJ=`aws ec2 describe-instances --region $Region --filters "Name=instance.group-id,Values=$SgId" --query 'Reservations[].Instances[].[InstanceId,[NetworkInterfaces[].PrivateIpAddress]]' --output text`
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
  NODELIST=`getnodelist $Role ip`
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
            
            umount -f ${args[0]};mkswap -f ${args[0]};swapon ${args[0]}
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
  yum -y install traceroute pdsh unzip oracle-rdbms-server-12cR1-preinstall tigervnc-server screen nfs-utils dnsmasq scsi-target-utils iscsi-initiator-utils firefox.x86_64 xrdp expect tinc patch
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
  if [ "$1" = "self" ] ; then
	InstanceId=$MyInstanceId
  else
	InstanceId=$1 	
  fi
  

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
  SgId=`getsgid $SgName`

  if [ "$SgId" != "" ] ; then
 	aws ec2 delete-security-group --group-id $SgId --region $Region > /dev/null
 	sleep 20
  fi
  SgId=`aws ec2 create-security-group --group-name $SgName --description "$SgName"  --vpc-id $VpcId --region $Region --query 'GroupId' --output text`
  sleep 20
  aws ec2 authorize-security-group-ingress --group-id $SgId --cidr $MyNetwork/16 --protocol -1 --port -1 --region $Region > /dev/null


  echo $SgId

}



requestspotinstances(){
	for Role in "${Roles[@]}"
	do
        	SgId=`createsecuritygroup ${Role}`
        	DeviceJson=`createdevicejson ${Role}`
        	PARAMS=($Role)
		#${PARAMS[0]} RoleName ${PARAMS[2]} instance count
		addspotinstances ${PARAMS[0]} ${PARAMS[2]}
	done

	waitrequest
	setnodelist
	waitreboot
	
}

waitrequest(){
	local Role
	local waittime=0
	for Role in "${Roles[@]}"
	do
		
        	PARAMS=($Role)
        	SgName=`getsgname ${PARAMS[0]}`
		SgId=`getsgid $SgName`
		isSend=0
		#${PARAMS[0]} RoleName ${PARAMS[2]} instance count
		instancecount=${PARAMS[2]}
		requestcount=`aws ec2 describe-spot-instance-requests --region $Region --filters "Name=launch.group-id,Values=$SgId" --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
		while [ $instancecount != $requestcount ]
		do
			sleep 10
			waittime=`expr $waittime + 10`
			if [ "$waittime" -ge "$MAXREQUESTWAIT" ]; then
				if [ "$isSend" != 1 ]; then
					TOPICARN=`gettopic $LAUNCHGROUP`
					publishtopic $TOPICARN "${PARAMS[0]} is requested  $instancecount now $requestcount"
					isSend=1
				fi				
			fi
 			requestcount=`aws ec2 describe-spot-instance-requests --region $Region --filters "Name=launch.group-id,Values=$SgId" --query 'SpotInstanceRequests[].Status[].Code' | grep "fulfilled" | wc -l`
		done
	done


}

#$1 Role $2 add instance count
addspotinstances()
{
	local Role
	for Role in "${Roles[@]}"
	do
		local PARAMS=($Role)
		if [ "$1" = "${PARAMS[0]}" ]; then
			SgName=`getsgname ${PARAMS[0]}`
			SgId=`getsgid $SgName`
    
	        	DeviceJson=`createdevicejson ${Role}`

        		if [ "$DeviceJson" != "" ]; then
        			Json={\"ImageId\":\"${PARAMS[4]}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${PARAMS[1]}\",\"BlockDeviceMappings\":$DeviceJson,\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"${SgId}\"]}
        		else
        			Json={\"ImageId\":\"${PARAMS[4]}\",\"KeyName\":\"${KEY_NAME}\",\"InstanceType\":\"${PARAMS[1]}\",\"SubnetId\":\"${SubnetId}\",\"SecurityGroupIds\":[\"${SgId}\"]}
        		fi
        
        		aws ec2 request-spot-instances --spot-price ${PARAMS[3]} --region $Region --launch-group $LAUNCHGROUP --launch-specification $Json --instance-count ${2} 
        	fi
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
	#SERVER=`getnodelist storage ip`
	#echo "supersede domain-name-servers ${SERVER};" >> /etc/dhcp/dhclient-eth0.conf
	echo "supersede domain-name-servers 127.0.0.1;" >> /etc/dhcp/dhclient-eth0.conf
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
        	LIST=`getnodelist $RoleName ip`
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
      cat > /etc/dnsmasq.conf <<EOF
domain-needed
bogus-priv
expand-hosts
domain=${NETWORK_NAME[0]}
EOF
    chkconfig dnsmasq on
    /etc/init.d/dnsmasq start


}


pretincconf()
{
  rm -rf $WORK_DIR/hosts
  rm -rf $WORK_DIR/rsa_key.priv
  rm -rf $WORK_DIR/tinc.conf
  mkdir -p $WORK_DIR/hosts
  cat > $WORK_DIR/tinc.conf <<EOF
Name = dummy
Interface = tap0
Mode = switch
BindToAddress * 655
MaxTimeout = 5

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
	mkdir /etc/tinc/
	
	PORT=655
	for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
	do
    		NETNAME=${NETWORK_NAME[$k]}
    		NODENAME=`getmyname`
    		
    		echo $NETNAME >> /etc/tinc/nets.boot
    		echo "tinc          ${PORT}/tcp             #TINC" >> /etc/services
    		echo "tinc          ${PORT}/udp             #TINC" >> /etc/services
    		mkdir -p /etc/tinc/$NETNAME
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
        		LIST=`getnodelist $RoleName ip`
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
			#
			#myNumber2=`expr $myNumber + 1`
			#NODECOUNT2=`expr $myNumber2 % ${#LIST[@]}`
			#NODECOUNT2=`expr $NODECOUNT2 + 1`
			#NODENAME2=`getnodename tinc $NODECOUNT2`
			#echo "ConnectTo = $NODENAME2" >> /etc/tinc/$NETNAME/tinc.conf
			
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

    chmod 755 /home/grid/grid.rsp
    chmod 755 /home/grid/asm.rsp
    chown grid.oinstall /home/grid/grid.rsp
    chown grid.oinstall /home/grid/asm.rsp
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

createsshkey()
{
    ALLCOUNT=1
    for Role in "${Roles[@]}"
    do
        	PARAMS=($Role)
        	RoleName=${PARAMS[0]}
        	LIST=`getnodelist $RoleName ip`
        	NODECOUNT=1
		for i in $LIST ;
		do
			echo "`getnodename $RoleName $NODECOUNT`,`getip 0 real $ALLCOUNT` `cat /etc/ssh/ssh_host_rsa_key.pub`" >> $WORK_DIR/known_hosts
			NODECOUNT=`expr $NODECOUNT + 1`
			ALLCOUNT=`expr $ALLCOUNT + 1`
		done
    done	
for user in oracle grid
do
	rm -rf /home/$user/.ssh
        mkdir /home/$user/.ssh
        cat /root/.ssh/authorized_keys >> /home/$user/.ssh/authorized_keys
        cp $KEY_PAIR /home/$user/.ssh/id_rsa
        cp $WORK_DIR/known_hosts /home/$user/.ssh/known_hosts
#        cat >> /home/$user/.ssh/config <<'EOF'
#host *        
#StrictHostKeyChecking no
#UserKnownHostsFile=/dev/null
#EOF
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
	SECOND_IFS=$IFS
    local IFS=':'
    local args=(${ORACLE_HOME_DEVICE})
    local IFS=$SECOND_IFS
    sfdisk -uM ${args[0]} <<EOF
,,83
EOF
    sleep 15
    mkfs.ext3 -F ${args[0]}1
}

mountoraclehome()
{
    SECOND_IFS=$IFS
    local IFS=':'
    local args=(${ORACLE_HOME_DEVICE})
    local IFS=$SECOND_IFS	
	
    echo "${args[0]}1               ${MOUNT_PATH}                    ext3    defaults        0 0" >> /etc/fstab
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
	local RETCODE=0
	curtime=`date +"%Y-%m%d-%H%M"`
	log_dir="./logs/${curtime}"
	mkdir -p $log_dir
	echo "`date` request start" >> $log_dir/main.log
	requestspotinstances
	pretincconf
	copyfile all work
	copyfile all $0
	copyfile all oswbb*.tar
	
	#for storage
  	dsh storage "sh $0 changesysstat;sh $0 changehostname;sh $0 createtgtd;reboot"
  	#for tinc
  	dsh tinc "sh $0 changesysstat;sh $0 changehostname;sh $0 createtincconf;reboot"
  	waitreboot
  	
  	#for node
  	dsh node "sh $0 changehostname;sh $0 createswap;sh $0 setupdns;sh $0 setdhcp;sh $0 createsshkey"
  	dsh node "sh $0 mountoraclehome;sh $0 cleangridhome;sh $0 setupiscsi;sh $0 createtincconf"
  	dsh node "sh $0 changesysstat;sh $0 creatersp;sh $0 createclonepl;reboot"
	waitreboot
	
	dsh all "sh $0 exeoswatcher"
	
	echo "`date` install grid infrastructure" >> $log_dir/main.log
	installgridsoftware
	
	echo "`date` config.sh"  >> $log_dir/main.log
	local RETCODE=`exessh node 1 "sh $0 execonfigsh"`
	if [ $RETCODE != 0 ] ; then
		local TOPICARN=`gettopic $LAUNCHGROUP`
		publishtopic $TOPICARN "config.sh failed" &> /dev/null
		exit
	fi
	
	echo "`date` root.sh 1st node"  >> $log_dir/main.log
	exe1strootsh
	echo "`date` root.sh other node" >> $log_dir/main.log
	exeotherrootsh
	
	echo "`date` install oracle software" >> $log_dir/main.log
	installoraclesoftware
	
	echo "`date` dbca" >> $log_dir/main.log
	exedbca
	
	echo "`date` end of state " >> $log_dir/main.log
	getgridstatus >> $log_dir/main.log
	

	getlogs $log_dir
	
	#end of this test
	terminate
  
}

exedbca(){
	dbcaoption="-silent -createDatabase -templateName $TEMPLATENAME -gdbName $DBNAME -sid $SIDNAME" 
	dbcaoption="$dbcaoption -SysPassword $SYSPASSWORD -SystemPassword $SYSTEMPASSWORD -emConfiguration NONE -redoLogFileSize $REDOFILESIZE"
	dbcaoption="$dbcaoption -recoveryAreaDestination $FRA -storageType ASM -asmSysPassword $ASMPASSWORD -diskGroupName $DISKGROUPNAME"
	dbcaoption="$dbcaoption -characterSet $CHARSET -nationalCharacterSet $NCHAR -totalMemory $MEMORYTARGET -databaseType $DATABASETYPE"

  	local NODECOUNT=1
  	local NODELIST=`getnodelist node ip`
  	for i in $NODELIST ;
	do
		if [ $NODECOUNT = 1 ] ; then
			dbcaoption="$dbcaoption -nodelist `getnodename $1 $NODECOUNT`"
		else
			dbcaoption="$dbcaoption,`getnodename $1 $NODECOUNT`"
		fi
			NODECOUNT=`expr $NODECOUNT + 1`
	done
	exessh node 1 "sudo -u oracle $ORA_ORACLE_HOME/bin/dbca $dbcaoption"
}

getgridstatus()
{
	exessh node 1 "sh $0 gridstatus"
}
gridstatus()
{
	
	cat > /home/grid/asmused.sh <<'EOF'
#!/bin/bash
export ORACLE_SID=+ASM1
source /home/grid/.bash_profile
crsctl status resource -t
sqlplus -s / as sysdba << EOL
	select group_number, name, total_mb, free_mb,total_mb - free_mb from v\$asm_diskgroup;
	exit;
EOL
EOF
	chmod 755 /home/grid/asmused.sh
	chown grid.oinstall /home/grid/asmused.sh
	sudo -u grid sh /home/grid/asmused.sh
}


waitreboot()
{
	sleep 30
	CMD="pdsh -R ssh -t 10 -w ^$WORK_DIR/all.ip -S date"
	$CMD
	RET=$?
	while [ $RET != 0 ]
	do
		sleep 10
		$CMD
		RET=$?
	done
}

dsh()
{
	pdsh -R ssh -w ^$WORK_DIR/$1.ip $2 $3 $4 $5 $6 $7 $8
}

setupallforclone(){

  
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
  
}

exessh()
{
	hostip=`getnodeip $1 $2`
	ssh $SSH_ARGS_APPEND root@${hostip} $3 $4 $5 $6 $7 $8 $9
}

catrootsh()
{
  exessh $1 $2 "ls $GRID_ORACLE_HOME/install/root* | sort -r | head -n 1 | xargs cat"
}

updatescript()
{
  curl https://raw.githubusercontent.com/s4ragent/ec2rac/master/${0}?id=${RANDOM} -o ${0}
  if [ "$1" = "copy" ] ; then
	copyfile all $0
  fi
}

copyfile()
{
  LIST=`getnodelist $1 ip`
  for i in $LIST ;
  do
    scp $SCP_ARGS_APPEND -r $2 root@$i:/root/
  done
}


#$1 RoleName $2 remotedir(getdir) $3 localdir
getfile()
{
  LIST=`getnodelist $1 ip`
  NODECOUNT=1
  for i in $LIST ;
  do
  	localdir=$3/`getnodename $1 $NODECOUNT`$2
        mkdir -p $localdir
        scp $SCP_ARGS_APPEND -r root@$i:$2 $localdir
        NODECOUNT=`expr $NODECOUNT + 1`
  done
}

exeoswatcher(){
	local myRole=`getmyrole`
	rm -rf oswbb
	tar xvf oswbb*.tar
	if [ "$myRole" = "node" ] ; then
		local LIST=`getnodelist node ip`
		local NODECOUNT=1
		echo 'echo "zzz ***"`date`' > oswbb/private.net
		for i in $LIST ;
		do
			echo "traceroute -r -F `getip 1 real $NODECOUNT`" >> oswbb/private.net
			NODECOUNT=`expr $NODECOUNT + 1`
		done
		echo "rm locks/lock.file" >> oswbb/private.net
		chmod 755 oswbb/private.net
	fi
	cd oswbb
	nohup ./startOSWbb.sh 5 10  &
	sleep 10
}

getlogs()
{
  getfile node /var/log/messages $1
  getfile tinc /var/log/messages $1
  getfile storage /var/log/messages $1
  getfile node $GRID_ORACLE_HOME/log $1
  getfile node $GRID_ORACLE_HOME/install/root* $1
  getfile node $ORAINVENTORY/logs $1
  getfile node /var/log/tinc.log $1
  getfile tinc /var/log/tinc.log $1
  #getfile node /root/oswbb/archive $1
  #getfile node /root/oswbb/analysis $1
  #getfile tinc /root/oswbb/archive $1
  #getfile tinc /root/oswbb/analysis $1
  #getfile storage /root/oswbb/archive $1
  #getfile storage /root/oswbb/analysis $1
}

installgridsoftware()
{
	dsh node -u 900 "sudo -u grid /home/grid/start.sh;$ORAINVENTORY/orainstRoot.sh"
	local RET=$?
	if [ $RET != 0 ] ; then
		dsh node dsh node -u 900 "sudo -u grid /home/grid/start.sh;$ORAINVENTORY/orainstRoot.sh"
	fi
	local RET=$?
	if [ $RET != 0 ] ; then
		TOPICARN=`gettopic $LAUNCHGROUP`
		publishtopic $TOPICARN "/home/grid/start.sh not finished" &> /dev/null
	fi

}

installoraclesoftware()
{
	dsh node -u 900 "sudo -u oracle /home/oracle/start.sh;$ORA_ORACLE_HOME/root.sh -silent"
	local RET=$?
	if [ $RET != 0 ] ; then
		dsh node dsh node -u 900 "sudo -u oracle /home/oracle/start.sh;$ORA_ORACLE_HOME/root.sh -silent"
	fi
	local RET=$?
	if [ $RET != 0 ] ; then
		TOPICARN=`gettopic $LAUNCHGROUP`
		publishtopic $TOPICARN "/home/oracle/start.sh not finished" &> /dev/null
	fi

}

execonfigsh()
{
	sudo -u grid $GRID_ORACLE_HOME/crs/config/config.sh -silent -responseFile /home/grid/grid.rsp &> /dev/null
	local RET=`echo $?`
	echo $RET
}

exe1strootsh(){
	exessh node 1 "sh $0 exerootsh"
}

exeotherrootsh()
{
	#create hosts file
	cp -f /etc/hosts $WORK_DIR/hosts.back
	echo "127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 `hostname -s`" >/etc/hosts
	echo "::1         localhost localhost.localdomain localhost6 localhost6.localdomain6" >> /etc/hosts
	  
	LIST=`getnodelist node ip`
	NODECOUNT=1
	cat "" > $WORK_DIR/rootsh.list
	for i in $LIST ;
	do
	    echo `getnodename node $NODECOUNT` >> $WORK_DIR/rootsh.list
	    echo "$i `getnodename $NODECOUNT`" >> /etc/hosts
	    NODECOUNT=`expr $NODECOUNT + 1`
	done
	pdsh -R ssh -w ^$WORK_DIR/rootsh.list -x `getnodename node 1` -f $PARALLEL "sh $0 exerootsh"
	
	cp -f $WORK_DIR/hosts.back /etc/hosts
}

exerootsh()
{
  $GRID_ORACLE_HOME/crs/install/rootcrs.pl -deconfig -force -verbose &> /dev/null
  $GRID_ORACLE_HOME/root.sh -silent &> /dev/null
  RET=$?
  if [ $RET != 0 ] ; then
  	TOPICARN=`gettopic $LAUNCHGROUP`
	publishtopic $TOPICARN "root.sh `hostname -s` fail " &> /dev/null
	#echo `hostname -s`
  fi
}

gettopic()
{
	local CNT=`aws sns list-topics --region $Region --output text | grep  $1  | wc -l`
	if [ $CNT != 0 ]; then
            	TOPICARN=`aws sns list-topics --region $Region --output text | grep  $1 | awk '{split ($0,a); print a[2]}'`
        else
        	TOPICARN=`aws sns create-topic --region $Region --name $1  --output text`
        	echo "input email"
        	read EMAILADDR
        	aws sns subscribe --region $Region --topic-arn $TOPICARN --protocol email --notification-endpoint $EMAILADDR >/dev/null
        fi
        echo $TOPICARN
		
}

#$1 TOPICARN $2 messages
publishtopic()
{
	aws sns publish --region $Region --topic-arn $1 --message "$2 $3 $4 $5 $6 $7 $8 $9"
}

testtopic()
{
	TOPICARN=`gettopic $1`
	publishtopic $TOPICARN "$2 $3 $4 $5 $6 $7 $8 $9"
}

changesysstat()
{
cat >/etc/cron.d/sysstat <<EOF
# Run system activity accounting tool every 10 minutes
* * * * * root /usr/lib64/sa/sa1 1 59
# 0 * * * * root /usr/lib64/sa/sa1 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * root /usr/lib64/sa/sa2 -A
EOF
}

case "$1" in
  "changesysstat" ) changesysstat;;
  "exerootsh" ) exerootsh $1 $2;;
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
   "addspotinstances" ) addspotinstances $2 $3 $4 $5;;
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
  "exessh" ) exessh $2 $3 $4 $5 $6 $7 $8;;
  "catrootsh" ) catrootsh $2;;
  "updatescript" ) updatescript $2;;
  "checktinc" ) checktinc $2;;
  "createdevicejson" ) createdevicejson $2;;
  "test" ) test;;
  "copyfile" ) copyfile $2 $3;;
  "dsh" ) dsh $2 $3 $4 $5 $6 $7 $8 $9;;
  "setdhcp" ) setdhcp;;
  "createtgtd" ) createtgtd;;
  "waitreboot" ) waitreboot;;
  "mountoraclehome" ) mountoraclehome;;
  "gridstatus" ) gridstatus;;
  "createdbcaoption" ) createdbcaoption $2;;
  "gettopic" ) gettopic $2;;
  "publishtopic" ) publishtopic $2 $3 $4 $5 $6 $7 $8 $9;;
  "testtopic" ) testtopic $2 $3 $4 $5 $6 $7 $8 $9;;
  "waitrequest" ) waitrequest;;
  "exeoswatcher" ) exeoswatcher;;
  "installgridsoftware" ) installgridsoftware;;
  "installoraclesoftware" ) installoraclesoftware;;
  "execonfigsh" ) execonfigsh;;
  "exe1strootsh" ) exe1strootsh;;
  "exeotherrootsh" ) exeotherrootsh;;
  "exedbca" ) exedbca;;
  "getgridstatus" ) getgridstatus;;
  * ) echo "Ex \"sh -x $0 setupallforclone c1.xlarge 1 m3.medium 10 2400 0\" 2400 means memorytarget, 0 means wait 0 seconds when grid root.sh" ;;
esac
