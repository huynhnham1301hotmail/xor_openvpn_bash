# Install updates.
apt-get -y update
apt-get -y upgrade
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Read public IP address and use that in the configurations.
collected_ip=$(dig +short myip.opendns.com @resolver1.opendns.com)
echo -e "\n############################################################################\n"
echo -e "This will be the IP address used for the server, in most cases it's simply"
echo -e "the public one being displayed. If you are typical, press enter.\n"
echo -e "############################################################################\n"

# If they click enter will save the variable as the default.
while true; do
    read -p "Enter server IP: [$collected_ip] " public_ip
    if [ -z "$public_ip" ];
        then 
            public_ip=$collected_ip
            break
        else

        # If they input an IP check the validity.
        if [[ "$(basename $0 .sh)" == 'main' ]]; then
            if valid_ip $public_ip;
                then break;
                else echo -e "That was not a valid IP, if you don't know what you're doing, simply click enter.\n";
            fi
        fi
    fi
done

# Add lines to the file.
cat <<EOF >>/etc/sysctl.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
# Create downloads for the wgets.
mkdir ~/Downloads
cd ~/Downloads

# Download wget source code.
wget https://swupdate.openvpn.org/community/releases/openvpn-2.5.8.tar.gz
tar xvf openvpn-2.5.8.tar.gz

# Copy files to this folder.
cp -r $DIR/patches/*.diff openvpn-2.5.8
cd openvpn-2.5.8/

# Apply all patches
patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff

# Install prereqs
apt-get install -y build-essential libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config

# Build openvpn
./configure --enable-systemd --enable-async-push --enable-iproute2
make
make install

# Create directories, these may already exist.
mkdir /etc/openvpn
mkdir /etc/openvpn/server
mkdir /etc/openvpn/client

cd ~/Downloads

# Download Easy-Rsa.
wget https://github.com/OpenVPN/easy-rsa/archive/v3.1.2.tar.gz
tar -xvzf v3.1.2.tar.gz

# Create easy-rsa directories. There always seems to be a clone...
mkdir -p /usr/share/easy-rsa/3
cp -rf easy-rsa-3.1.2/* /usr/share/easy-rsa/3

# Make the example the real file.
cd /usr/share/easy-rsa/3/easyrsa3
cp vars.example vars

# Generate easyrsa.
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req $public_ip nopass
./easyrsa sign-req server $public_ip
./easyrsa gen-req adminpc nopass
./easyrsa sign-req client adminpc
./easyrsa gen-dh

# Copy pki files to the opencpn server and client.
cp pki/ca.crt /etc/openvpn
cp pki/dh.pem /etc/openvpn/server
cp pki/issued/$public_ip.crt /etc/openvpn/server
cp pki/issued/adminpc.crt /etc/openvpn/client
cp pki/private/ca.key /etc/openvpn
cp pki/private/$public_ip.key /etc/openvpn/server
cp pki/private/adminpc.key /etc/openvpn/client

# Generate encryption key.
cd /etc/openvpn
openvpn --genkey --secret tls-crypt.key

# Give read permissions.
chmod +r ca.crt
chmod +r client/adminpc.crt
chmod +r client/adminpc.key
chmod +r tls-crypt.key

# Create hash.
cd /etc/openvpn
openssh_hash=$(openssl rand -base64 24)

# Add scrable hash to the server configuration file.
cat << EOF > server/$public_ip.conf
port 443
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server/$public_ip.crt
key /etc/openvpn/server/$public_ip.key
dh /etc/openvpn/server/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
cipher AES-256-GCM
tls-crypt /etc/openvpn/tls-crypt.key
persist-key
persist-tun
status openvpn-status.log
verb 3
scramble obfuscate $openssh_hash
EOF



###############################################
# TODO
###############################################
# Change the location of reading in the patches
# to be local rather than pulling from the
# master.zip @ tunnelblick.
#
# Make the script more secure with options
