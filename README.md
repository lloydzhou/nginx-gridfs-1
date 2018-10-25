## About
gridfs module for nginx.  
>
forked from nieoding/nginx-gridfs
Thanks for nieoding add the support for MongoDB SCRAM-SHA-1 auth connection


## Version
support _id and filename for PrimaryKey

## Installation
> only test build on Ubuntu and nginx 1.13.9
> Download and install mongo-c-driver-1.9.2.tar.gz
```bash
cat /usr/local/lib >> /etc/ld.so.conf
ldconfig
```
cd to nginx src directory and configure with --add-module=/path/to/ngixn-gridfs/
## Config
```ini
# nginx.conf
location /media/ {
    gridfs db_name field=_id(filename) type=objectid(string);
    mongo mongodb://username:password@127.0.0.1:27017/db_name;
}
```
> mongo connect-uri follow [the official format](https://docs.mongodb.com/manual/reference/connection-string/)
> 
> mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]

