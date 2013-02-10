#!/bin/bash

# openssl shortcuts for quick testing 
# no error checking and silent overwriting!

# dir for users keys/certs/files
CLIPATH="./clients"

# size of keys
ROOTKEYSIZE="2048"
KEYSIZE="1024"

# root and child CA names/path - these must match the ones in openssl.cnf
CAPATH="./CAs"
CAKEYPATH="private/cakey.pem"
CACERTPATH="cacert.pem"
ROOT_CA_NAME='root_CA'
CHILD_CA_NAME='child_CA'

# file naming conventions
CLI_BASE='user_'
CLI_REQ='.req.pem'
CLI_CERT='.cert.pem'
CLI_DSAPARAM='.dsapar.pem'
CLI_PRIVKEY='.privkey.pem'
CLI_PUBKEY='.pubkey.pem'
CLI_MFILE='.hello.m'
CLI_RFILE='.hello.r'

CONFIRM_CMD="1"

showAndExec() {
	local CMD=$1
	echo $CMD

	if [ "$CONFIRM_CMD" = 1	]; then
		read -p ">> execute command? (y/n) " -n 1 confirm
	else
		confirm='y'
	fi
	echo
	if [ "$confirm" = 'y' ]; then
		eval $CMD		
	fi	
	
}
####################################################################

# create a new CA dir structure
createCA() {
	local CA=$1
	mkdir $CA
	mkdir $CA/newcerts $CA/private
	chmod g-rwx,o-rwx $CA/private
	echo 01 > $CA/serial
	touch $CA/index.txt
}

# setup root CA with self signed DSA cert
createCA_root() {
	CA=$CAPATH/$ROOT_CA_NAME
	createCA $CA

	# dsaparam - create DSA parameters p, q, g
	showAndExec "openssl dsaparam -out parameters.pem $ROOTKEYSIZE"

	# -newkey dsa:filename generates a DSA key using the parameters in the file filename.
	# self signed cert
	echo '>> remember to input a Common Name...'
	showAndExec "openssl req -config openssl.cnf -x509 -nodes -newkey dsa:parameters.pem -keyout $CA/$CAKEYPATH -out $CA/$CACERTPATH"
	rm parameters.pem
}

createCA_child() {
	CA=$CAPATH/$CHILD_CA_NAME
	createCA $CA

	showAndExec "openssl dsaparam -out parameters.pem $KEYSIZE"
	
	echo '>> remember to input a Common Name...'
	showAndExec "openssl req -config openssl.cnf -nodes -newkey dsa:parameters.pem -keyout $CA/$CAKEYPATH -out req.pem"

	# root CA issues cert for child CA
	showAndExec "openssl ca -config openssl.cnf -name $ROOT_CA_NAME -in req.pem -out $CA/$CACERTPATH"

	rm parameters.pem
	rm req.pem
}

setup() {
	if [ -d "$CAPATH" ]; then
		read -p ">> ready to delete everything and restart testing - proceed? (y/n) " -n 1 confirm
		echo
		if [ "$confirm" != 'y' ]; then
			return 0
		fi
	fi	
	echo '>> cleaning paths'
	rm -rf $CAPATH $CLIPATH
	echo '>> creating dirs'
	mkdir $CAPATH $CLIPATH
	echo '>> press any key to start creation of root CA (self signed certificate)'
	read -n1 junk
	createCA_root
	echo '>> press any key to start creation of child CA (CSR to root CA, root CA issues the certificate)'
	read -n1 junk
	createCA_child
	echo '>> creating certificate chain'
	showAndExec "cat $CAPATH/$ROOT_CA_NAME/$CACERTPATH $CAPATH/$CHILD_CA_NAME/$CACERTPATH > $CAPATH/chain.pem"
}

####################################################################à

writeTestMfile() {
	local cli=$CLIPATH/$CLI_BASE$1	
	showAndExec "echo \"Hello world, this is $1!\" > $cli$CLI_MFILE"
}

createDSAkey() {
	local cli=$CLIPATH/$CLI_BASE$1	
	showAndExec "openssl dsaparam -out $cli$CLI_DSAPARAM $KEYSIZE"
	showAndExec "openssl gendsa -out $cli$CLI_PRIVKEY $cli$CLI_DSAPARAM"
	#showAndExec "openssl dsa -pubout -in $cli$CLI_PRIVKEY -out $cli$CLI_PUBKEY"
} 

createRSAkey()  {
	local cli=$CLIPATH/$CLI_BASE$1	
	showAndExec "openssl genrsa -out $cli$CLI_PRIVKEY $KEYSIZE"
	#showAndExec "openssl rsa -pubout -in $cli$CLI_PRIVKEY -out $cli$CLI_PUBKEY"
}

####################################################################

#global vars
G_SELECTED_CA=""
G_SELECTED_USER=""

selectUser() {
	# save and change IFS
	OLDIFS=$IFS
	IFS=$'\n' 
	 
	fileArray=($(find $CLIPATH -type f | grep $CLI_PRIVKEY))
	 
	# restore it
	IFS=$OLDIFS
	 
	# get length of an array
	tLen=${#fileArray[@]}
	
	echo 
	
	for (( i=0; i<${tLen}; i++ ));
	do
		tmp=$(basename "${fileArray[$i]}")
		tmp2=${tmp%%.*}
		fileArray[$i]=${tmp2/$CLI_BASE/}
		echo "$i) ${fileArray[$i]}"	
	done
	
	if [ $tLen = 0 ]; then 
		echo ' - no users defined!'
	else 
		if [ $# = 0 ]; then
			read -p ">> which one? " -n 1 i
			G_SELECTED_USER=$CLIPATH/$CLI_BASE${fileArray[$i]}	
			echo
		fi
	fi
}

selectCA() {
	caArray=($ROOT_CA_NAME $CHILD_CA_NAME)
	echo
	echo "0) ${caArray[0]}"
	echo "1) ${caArray[1]}"
	read -p ">> which one? " -n 1 i
	G_SELECTED_CA=${caArray[$i]}
	echo
}

####################################################################

menu() {
	clear
	echo '================================================================'
	echo '== PKI and commitment testing environment =='
	echo '================================================================'
	echo '1) setup: create/reset testing environment (new root_CA and child_CA, no users)'	
	
	if [ ! -d "$CLIPATH" ] ; then
		return 0
	fi	
	echo '== Users =='
	echo 'l) show users list'
	echo 'n) new user (RSA key and example m_file)'
	echo 'm) new user (DSA key and example m_file)'
	echo 'r) new CSR for $username (plain CSR using openssl req, no commitment)'
	echo ' c) commitment - edit CSR for $username, $m_file, $ca (using commitment_req)'
	echo ' d) decomittment -  check for $username, $m_file, $ca (using commitment_chk)'
	echo '========================'
	echo
	echo '== CA =='
	echo 'i) issue certificate for CSR of client $username with CA $ca'
	echo ' u) decommitment - check CSR before issuing cert (using commitment_req)'
	echo '========================'
	echo 
	echo '== other =='
	echo 'q) view CSR of $username in text form'
	echo 'a) view certificate of $username in text form'
	echo 'z) view certificate of $ca in text form'
	echo
	echo 'w) verify signature of CSR by $username'
	echo 's) verify certificate of $username'
	echo 'x) verify certificate of $ca'
	echo '================================================================'
	echo 'e) exit'
	echo 
}

while [ true ]; do
	menu
	read -p ">> ? " -n1 selectedOpt
	echo
	case "$selectedOpt" in
		1) #setup: create test environment (root_CA and child_CA, clients dir)
			setup
			;;
		l) # show users list
			selectUser showOnly
			;;
		n) #new user (RSA key and example m_file)
			echo -n ">> username? "
			read username
			createRSAkey $username
			writeTestMfile $username
			;;
		m) #new user (DSA key and example m_file)
			echo -n ">> username? "
			read username
			createDSAkey $username
			writeTestMfile $username
			;;
		r) #new CSR for $username (plain CSR using openssl req, no commitment)'
			selectUser
			showAndExec "openssl req -config openssl.cnf -new -key $G_SELECTED_USER$CLI_PRIVKEY -out $G_SELECTED_USER$CLI_REQ"
			;;
		c) #edit CSR for $username, $m_file, $caName (commitment)
			selectUser
			selectCA			
			showAndExec "./commitment_req -v -CAcert $CAPATH/$G_SELECTED_CA/$CACERTPATH -key $G_SELECTED_USER$CLI_PRIVKEY -in $G_SELECTED_USER$CLI_MFILE -inreq $G_SELECTED_USER$CLI_REQ -outreq $G_SELECTED_USER$CLI_REQ -outR $G_SELECTED_USER$CLI_RFILE"
			;;						
		d) # do commitment check on certificate
			selectUser
			selectCA
			showAndExec "./commitment_chk -v -cert $G_SELECTED_USER$CLI_CERT -CAcert $CAPATH/$G_SELECTED_CA/$CACERTPATH -in $G_SELECTED_USER$CLI_MFILE -inR $G_SELECTED_USER$CLI_RFILE"
			;;		
		i) # issue certificate for CSR of client $username with CA $caName'
			selectUser
			selectCA
			showAndExec "openssl ca -config openssl.cnf -name $G_SELECTED_CA -in $G_SELECTED_USER$CLI_REQ -out $G_SELECTED_USER$CLI_CERT"
			;;			
		u) # do commitment check on CSR
			selectUser
			selectCA
			showAndExec "./commitment_chk -v -req $G_SELECTED_USER$CLI_REQ -CAcert $CAPATH/$G_SELECTED_CA/$CACERTPATH -in $G_SELECTED_USER$CLI_MFILE -inR $G_SELECTED_USER$CLI_RFILE"
			;;		
		q) # view CSR of $username in text form		
			selectUser
			showAndExec "openssl req -text -in $G_SELECTED_USER$CLI_REQ"
			;;		
		a) # view certificate of $username in text form
			selectUser
			showAndExec "openssl x509 -text -in $G_SELECTED_USER$CLI_CERT"
			;;		
		z) # view certificate of $ca in text form
			selectCA
			showAndExec "openssl x509 -text -in $CAPATH/$G_SELECTED_CA/$CACERTPATH"
			;;	
		w) # verify signature of CSR of $username
			selectUser
			showAndExec "openssl req -verify -in $G_SELECTED_USER$CLI_REQ -noout"
			;;
		s) # verify certificate of $username
			echo TODO
			selectUser
			showAndExec "openssl verify -CAfile $CAPATH/chain.pem -purpose any $G_SELECTED_USER$CLI_CERT"
			;;
		x) # verify certificate of $ca
			selectCA
			showAndExec "openssl verify -CAfile $CAPATH/chain.pem -purpose any $CAPATH/$G_SELECTED_CA/$CACERTPATH"
			;;
		e) # exit
			exit 0
			;;
		# g) # custom command
		#	read cmd
		#	eval $cmd
		#	;;
		
	esac
	echo ' - press any key to continue - '
	read -n1 junk	
done

