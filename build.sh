# # mongo-c-driver
# yum install -y epel-release	# update repo, so mongo-c-driver can bo searched.
# yum install -y mongo-c-driver-devel
# 
# # get and build nginx
# yum install -y wget
# yum install -y pcre-devel openssl-devel zlib-devel	# default nginx depends
# yum install -y gcc make	# build nginx
# wget http://nginx.org/download/nginx-1.12.2.tar.gz
# tar -xf nginx-1.12.2.tar.gz
# cd nginx-1.12.2
# ./configure --with-openssl=/usr/include/openssl --add-module=../nginx-gridfs/
# make install
# ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx
# 
# # clear
# rm -rf /tmp/*
# yum clean all

export NGINX_VERSION="1.19.9"
apt update && apt install -y git wget gcc make libmongoc-dev libpcre3-dev libssl-dev zlib1g-dev
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -O nginx.tar.gz
tar -xf nginx.tar.gz && cd nginx-${NGINX_VERSION}
./configure --add-module=../nginx-gridfs/
make install

