#!/bin/bash

export BITCOIN="bitcoin-core-0.21.0"
export CLN_VERSION="v0.9.2"
export LIGHTNING_DIR="/home/$USER/.lightning"
export FULL_BTC_DATA_DIR="/home/$USER/.bitcoin"
export CLN_HTTP_PLUGIN="Y"
USER=satoshi

HTTP_PASS=$(xxd -l 16 -p /dev/urandom)

SCRIPTS_DIR=$(pwd)

# rsync "/Users/matthiasdebernardini/Library/Application Support/Bitcoin/testnet3/utxo.dat" root@95.179.136.252:/home/$USER/.bitcoin/testnet3/
# DISCLAIMER: It is not a good idea to store large amounts of Bitcoin on a VPS,
# ideally you should use this as a watch-only wallet. This script is expiramental
# and has not been widely tested. The creators are not responsible for loss of
# funds. If you are not familiar with running a node or how Bitcoin works then we
# urge you to use this in tesnet so that you can use it as a learning tool.

# This script installs the latest stable version of Tor, Bitcoin Core,
# Uncomplicated Firewall (UFW), debian updates, enables automatic updates for
# debian for good security practices, installs a random number generator, and
# optionally a QR encoder and an image displayer.

# The script will display the uri in plain text which you can convert to a QR Code
# yourself. It is highly recommended to add a Tor V3 pubkey for cookie authentication
# so that even if your QR code is compromised an attacker would not be able to access
# your node.

# $USER.sh sets Tor and Bitcoin Core up as systemd services so that they start
# automatically after crashes or reboots. By default it sets up a pruned testnet node,
# a Tor V3 hidden service controlling your rpcports and enables the firewall to only
# allow incoming connections for SSH. If you supply a SSH_KEY in the arguments
# it allows you to easily access your node via SSH using your rsa pubkey, if you add
# SYS_SSH_IP's your VPS will only accept SSH connections from those IP's.

# $USER.sh will create a user called $USER, and assign the optional password you
# give it in the arguments.

# $USER.sh will create two logs in your root directory, to read them run:
# $ cat $USER.err
# $ cat $USER.log

####
#0. Prerequisites
####

# In order to run this script you need to be logged in as root, and enter in the commands
# listed below:

# (the $ represents a terminal commmand prompt, do not actually type in a $)

# First you need to give the root user a password:
# $ sudo passwd

# Then you need to switch to the root user:
# $ su - root

# Then create the file for the script:
# $ nano $USER.sh

# Nano is a text editor that works in a terminal, you need to paste the entire contents
# of this script into your terminal after running the above command,
# then you can type:
# control x (this starts to exit nano)
# y (this confirms you want to save the file)
# return (just press enter to confirm you want to save and exit)

# Then we need to make sure the script can be executable with:
# $ chmod +x $USER.sh

# After that you can run the script with the optional arguments like so:
# $ ./$USER.sh "insert pubkey" "insert node type (see options below)" "insert ssh key" "insert ssh allowed IP's" "insert password for $USER user"

####
# 1. Set Initial Variables from command line arguments
####

# The arguments are read as per the below variables:
# ./$USER.sh "PUBKEY" "BTCTYPE" "SSH_KEY" "SYS_SSH_IP" "USERPASSWORD"

# If you want to omit an argument then input empty qoutes in its place for example:
# ./$USER "" "Mainnet" "" "" "aPasswordForTheUser"

# If you do not want to add any arguments and run everything as per the defaults simply run:
# ./$USER.sh

# For Tor V3 client authentication (optional), you can run $USER.sh like:
# ./$USER.sh "descriptor:x25519:NWJNEFU487H2BI3JFNKJENFKJWI3"
# and it will automatically add the pubkey to the authorized_clients directory, which
# means the user is Tor authenticated before the node is even installed.
PUBKEY=$1

# Can be one of the following: "Mainnet", "Pruned Mainnet", "Testnet", "Pruned Testnet", or "Private Regtest", default is "Pruned Testnet"
BTCTYPE=$2

# Optional key for automated SSH logins to $USER non-privileged account - if you do not want to add one add "" as an argument
SSH_KEY=$3

# Optional comma separated list of IPs that can use SSH - if you do not want to add any add "" as an argument
SYS_SSH_IP=$4

# Optional password for the $USER non-privileged account - if you do not want to add one add "" as an argument
USERPASSWORD=$5

# Force check for root, if you are not logged in as root then the script will not execute
if ! [ "$(id -u)" = 0 ]
then

  echo "$0 - You need to be logged in as root!"
  exit 1

fi

# Output stdout and stderr to ~root files
exec > >(tee -a /root/$USER.log) 2> >(tee -a /root/$USER.log /root/$USER.err >&2)

####
# 2. Bring Debian Up To Date
####

echo "$0 - Starting Debian updates; this will take a while!"

# Make sure all packages are up-to-date
apt update
apt upgrade -y
apt dist-upgrade -y

# Install haveged (a random number generator)
apt install haveged -y

# Install GPG
apt install gnupg -y

# Install dirmngr
apt install dirmngr

# Set system to automatically update
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
apt -y install unattended-upgrades

echo "$0 - Updated Debian Packages"

# get uncomplicated firewall and deny all incoming connections except SSH
sudo apt install ufw -y
ufw allow ssh
ufw enable

####
# 3. Set Up User
####

# Create "$USER" user with optional password and give them sudo capability
/usr/sbin/useradd -m -p `perl -e 'printf("%s\n",crypt($ARGV[0],"password"))' "$USERPASSWORD"` -g sudo -s /bin/bash $USER
/usr/sbin/adduser $USER sudo

echo "$0 - Setup $USER with sudo access."

# Setup SSH Key if the user added one as an argument
if [ -n "$SSH_KEY" ]
then

   mkdir ~$USER/.ssh
   echo "$SSH_KEY" >> ~$USER/.ssh/authorized_keys
   chown -R $USER ~$USER/.ssh

   echo "$0 - Added .ssh key to $USER."

fi

# Setup SSH allowed IP's if the user added any as an argument
if [ -n "$SYS_SSH_IP" ]
then

  echo "sshd: $SYS_SSH_IP" >> /etc/hosts.allow
  echo "sshd: ALL" >> /etc/hosts.deny
  echo "$0 - Limited SSH access."

else

  echo "$0 - WARNING: Your SSH access is not limited; this is a major security hole!"

fi

####
# 5. Install Bitcoin
####

# Download Bitcoin
echo "$0 - Downloading Bitcoin; this will also take a while!"

# CURRENT BITCOIN RELEASE:
# Change as necessary

export BITCOINPLAIN=`echo $BITCOIN | sed 's/bitcoin-core/bitcoin/'`

sudo -u $USER wget https://bitcoincore.org/bin/$BITCOIN/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -O ~$USER/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz
sudo -u $USER wget https://bitcoincore.org/bin/$BITCOIN/SHA256SUMS.asc -O ~$USER/SHA256SUMS.asc
sudo -u $USER wget https://bitcoin.org/laanwj-releases.asc -O ~$USER/laanwj-releases.asc

# Verifying Bitcoin: Signature
echo "$0 - Verifying Bitcoin."

sudo -u $USER /usr/bin/gpg --no-tty --import ~$USER/laanwj-releases.asc
export SHASIG=`sudo -u $USER /usr/bin/gpg --no-tty --verify ~$USER/SHA256SUMS.asc 2>&1 | grep "Good signature"`
echo "SHASIG is $SHASIG"

if [[ "$SHASIG" ]]
then

    echo "$0 - VERIFICATION SUCCESS / SIG: $SHASIG"

else

    (>&2 echo "$0 - VERIFICATION ERROR: Signature for Bitcoin did not verify!")

fi

# Verify Bitcoin: SHA
export TARSHA256=`/usr/bin/sha256sum ~$USER/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz | awk '{print $1}'`
export EXPECTEDSHA256=`cat ~$USER/SHA256SUMS.asc | grep $BITCOINPLAIN-x86_64-linux-gnu.tar.gz | awk '{print $1}'`

if [ "$TARSHA256" == "$EXPECTEDSHA256" ]
then

   echo "$0 - VERIFICATION SUCCESS / SHA: $TARSHA256"

else

    (>&2 echo "$0 - VERIFICATION ERROR: SHA for Bitcoin did not match!")

fi

# Install Bitcoin
echo "$0 - Installinging Bitcoin."

sudo -u $USER /bin/tar xzf ~$USER/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -C ~$USER
/usr/bin/install -m 0755 -o root -g root -t /usr/local/bin ~$USER/$BITCOINPLAIN/bin/*
/bin/rm -rf ~$USER/$BITCOINPLAIN/

# Start Up Bitcoin
echo "$0 - Configuring Bitcoin."

sudo -u $USER /bin/mkdir ~$USER/.bitcoin

# The only variation between Mainnet and Testnet is that Testnet has the "testnet=1" variable
# The only variation between Regular and Pruned is that Pruned has the "prune=550" variable, which is the smallest possible prune
RPCPASSWORD=$(xxd -l 16 -p /dev/urandom)

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
server=1
rpcuser=$USER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1

EOF

if [ "$BTCTYPE" == "" ]; then

BTCTYPE="Signet"

fi

if [ "$BTCTYPE" == "Mainnet" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
txindex=1
EOF

elif [ "$BTCTYPE" == "Pruned Mainnet" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
prune=550
EOF

elif [ "$BTCTYPE" == "Testnet" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
dbcache=550
txindex=1
testnet=1
EOF

elif [ "$BTCTYPE" == "Pruned Testnet" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
prune=550
testnet=1
EOF

elif [ "$BTCTYPE" == "Signet" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
signet=1
EOF

elif [ "$BTCTYPE" == "Private Regtest" ]; then

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
regtest=1
txindex=1
EOF

else

  (>&2 echo "$0 - ERROR: Somehow you managed to select no Bitcoin Installation Type, so Bitcoin hasn't been properly setup. Whoops!")
  exit 1

fi

cat >> ~$USER/.bitcoin/bitcoin.conf << EOF
[test]
rpcbind=127.0.0.1
rpcport=18332
[main]
rpcbind=127.0.0.1
rpcport=8332
[regtest]
rpcbind=127.0.0.1
rpcport=18443
EOF

/bin/chown $USER ~$USER/.bitcoin/bitcoin.conf
/bin/chmod 600 ~$USER/.bitcoin/bitcoin.conf

# Setup bitcoind as a service
echo "$0 - Setting up Bitcoin as a systemd service."

sudo cat > /etc/systemd/system/bitcoind.service << EOF
# It is not recommended to modify this file in-place, because it will
# be overwritten during package upgrades. If you want to add further
# options or overwrite existing ones then use
# $ systemctl edit bitcoind.service
# See "man systemd.service" for details.
# Note that almost all daemon options could be specified in
# /etc/bitcoin/bitcoin.conf, except for those explicitly specified as arguments
# in ExecStart=
[Unit]
Description=Bitcoin daemon

[Service]
ExecStart=/usr/local/bin/bitcoind -conf=/home/$USER/.bitcoin/bitcoin.conf 
# Process management
####################
Type=simple
PIDFile=/run/bitcoind/bitcoind.pid
Restart=on-failure
# Directory creation and permissions
####################################
# Run as bitcoin:bitcoin
User=$USER
Group=sudo
# /run/bitcoind
RuntimeDirectory=bitcoind
RuntimeDirectoryMode=0710
# Hardening measures
####################
# Provide a private /tmp and /var/tmp.
PrivateTmp=true
# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full
# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true
# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true
# Deny the creation of writable and executable memory mappings.
MemoryDenyWriteExecute=true
[Install]
WantedBy=multi-user.target
EOF

echo "$0 - Starting bitcoind service"
sudo systemctl enable bitcoind.service
# sudo systemctl start bitcoind.service




# $USER script - install c-lightning
export MESSAGE_PREFIX="HI"
echo "
----------------
  $MESSAGE_PREFIX installing c-lightning
----------------
"



echo "$MESSAGE_PREFIX installing c-lightning dependencies"

apt install -y \
autoconf automake build-essential git libtool libgmp-dev \
libsqlite3-dev python3 python3-mako net-tools zlib1g-dev \
libsodium-dev gettext valgrind python3-pip libpq-dev

# dev tools
apt install -y rsync jq qrencode

echo "
$MESSAGE_PREFIX downloading & Installing c-lightning
"
# get & compile clightning from github
sudo -u $USER git clone https://github.com/ElementsProject/lightning.git ~$USER/lightning
cd ~$USER/lightning
git checkout $CLN_VERSION
python3 -m pip install -r requirements.txt
./configure
make -j$(nproc --ignore=1) --quiet
sudo make install

# get back to script directory
cd "$SCRIPTS_DIR"

# lightningd config
mkdir -m 760 "$LIGHTNING_DIR"
chown $USER -R "$LIGHTNING_DIR"
cat >> "$LIGHTNING_DIR"/config << EOF
alias=$USER
network=signet
log-level=debug:plugin
log-prefix=$USER

bitcoin-datadir=$FULL_BTC_DATA_DIR
bitcoin-rpcuser=$USER
bitcoin-rpcpassword=$RPCPASSWORD
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18332


# listen on all interfaces
bind-addr=
# listen only clearnet
bind-addr=127.0.0.1:9735


EOF

/bin/chmod 640 "$LIGHTNING_DIR"/config

# create log file
touch "$LIGHTNING_DIR"/lightning.log




echo "$MESSAGE_PREFIX Setting up c-lightning as a systemd service."

cat > /etc/systemd/system/lightningd.service << EOF
# It is not recommended to modify this file in-place, because it will
# be overwritten during package upgrades. If you want to add further
# options or overwrite existing ones then use
# $ systemctl edit bitcoind.service
# See "man systemd.service" for details.
# Note that almost all daemon options could be specified in
# /etc/lightning/config, except for those explicitly specified as arguments
# in ExecStart=
[Unit]
Description=c-lightning daemon

[Service]
ExecStart=/usr/local/bin/lightningd --conf=/home/$USER/.lightning/config
# Process management
####################
Type=simple
PIDFile=/run/lightning/lightningd.pid
Restart=on-failure
# Directory creation and permissions
####################################
# Run as lightningd:lightningd
User=$USER
Group=sudo
# /run/lightningd
RuntimeDirectory=lightningd
RuntimeDirectoryMode=0710
# Hardening measures
####################
# Provide a private /tmp and /var/tmp.
PrivateTmp=true
# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full
# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true
# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true
# Deny the creation of writable and executable memory mappings.
MemoryDenyWriteExecute=true
[Install]
WantedBy=multi-user.target
EOF

# enable lightnind service
sudo systemctl enable lightningd.service


echo "$0 - You can manually stop Bitcoin with: sudo systemctl start bitcoind.service && sudo systemctl start lightning.service"
echo "$0 - sudo systemctl status lightningd"
echo "$0 - systemctl status lightningd | grep active | awk '{print $2}'"

# Finished, exit script
exit 1
