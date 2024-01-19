#!/usr/bin/env bash

nginx_main_conf_file=$(couch_nginx_main=$(ps --no-headers o args $(pidof nginx) | grep 'master process' | head -n 1 | grep -oP "\s-c\s+([^'\"\s]\S*|'.*?'|\".*?\")" | sed -r "s/\s-c\s+//" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [ -n "$couch_nginx_main" ]; then echo "$couch_nginx_main"; else nginx -V 2>&1 | grep -oP "\s--conf-path=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--conf-path=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"; fi)


echo "[Manual]" 'Install the latest NGINX security hotfixes.
For example, run the following command: 
yum update nginx -y'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Consult the NGINX module documentation to determine which modules are needed for 
your specific installation. 
Modules may be removed using the configure command.
To explicitly remove modules from Nginx while installing from source, do:
# ./configure --without-module1 --without-module2 --without-module3
For example:
# ./configure  --without-http_dav_module --withouthttp_spdy_module 
Removing modules from a previous Nginx installation requires performing the compilation again.
Note: Configuration directives are provided by modules. Make sure you don’t disable a module that contains a directive you will need down the road! You should check the nginx docs for the list of directives available in each module before taking a decision on disabling modules.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remove the http_dav_module, recompile nginx from source without the --with-http_dav_module flag.

Default: the HTTP WebDAV module is not installed by default when installing from source. It does come by default when installed using yum.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In order to disable the http_gzip_module, nginx must be recompiled from source. 
The http_gzip_module is built by default. To disable it compile nginx with --without-http_gzip_module, like:
./configure --without-http_gzip_module
This must be done without the --with-http_gzip_static_module configuration directive to disable http_gzip_static_module. 

Default: The http_gzip_module is enabled by default in the source build, and the http_gzip_static_module is not. Both are enabled by default in the yum package.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/(\{|}|^|;)(\s*autoindex\s+on)(\s|;|$)/\1 ## \2\3/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/(\{|}|^|;)(\s*autoindex\s+on)(\s|;|$)/\1 ## \2\3/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/(\{|}|^|;)(\s*autoindex\s+on)(\s|;|$)/\1 ## \2\3/' "$couch_conffile"; done


echo "[Manual]" 'Add a system account for the nginx user with a home directory of /var/cache/nginx and a shell of /sbin/nologin so it does not have the ability to log in, then add the nginx user to be used by nginx: 
useradd nginx -r -g nginx -d /var/cache/nginx -s /sbin/nologin 
Then add the nginx user to /etc/nginx/nginx.conf by adding the user directive as shown below: 
user nginx;

Default: by default, if nginx is compiled from source, the user and group are nobody. If downloaded from yum, the user and group nginx and the account is not privileged.'
read -n 1 -p "Press Enter to continue..."


couch_nginx_user=$(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP '(\{|}|^|;)\s*user\s+\S+?(;|\s)' | tail -n 1 | sed -r 's/(\{|}|^|;)\s*user\s+//' | sed -r 's/\s*;?$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
[ -z "$couch_nginx_user" ] && couch_nginx_user=$(nginx -V 2>&1 | grep -oP "\s--user=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--user=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
if [ -n "$couch_nginx_user" ]; then passwd -l "$couch_nginx_user"; fi


couch_nginx_user=$(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP '(\{|}|^|;)\s*user\s+\S+?(;|\s)' | tail -n 1 | sed -r 's/(\{|}|^|;)\s*user\s+//' | sed -r 's/\s*;?$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
[ -z "$couch_nginx_user" ] && couch_nginx_user=$(nginx -V 2>&1 | grep -oP "\s--user=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--user=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
if [ -n "$couch_nginx_user" ]; then chsh -s /sbin/nologin "$couch_nginx_user"; fi


chown -R root:root "$(dirname "$nginx_main_conf_file")"


find -L "$(dirname "$nginx_main_conf_file")" \( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0020 \) | while read -r line; do chmod g-w,o-rwx "$line"; done


couch_nginx_conf_pid=$(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*pid\s+([^'\"]\S*|'.*?'|\".*?\")\s*;" | tail -n 1 | sed -r 's/(\{|}|^|;)\s*pid\s+//' | sed -r 's/\s*;$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
[[ -z "$couch_nginx_conf_pid" ]] && couch_nginx_conf_pid=$(nginx -V 2>&1 | grep -oP "\s--pid-path=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--pid-path=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
if [[ -n "$couch_nginx_conf_pid" ]]; then [[ "$couch_nginx_conf_pid" =~ ^/ ]] || couch_nginx_conf_pid=$(nginx -V 2>&1 | grep -oP "\s--prefix=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--prefix=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")/"$couch_nginx_conf_pid"; chown root:root "$couch_nginx_conf_pid"; chmod u-x,go-wx "$couch_nginx_conf_pid"; fi


couch_nginx_working_dir=$(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*working_directory\s+([^'\"]\S*|'.*?'|\".*?\")\s*;" | sed -r 's/(\{|}|^|;)\s*working_directory\s+//' | sed -r 's/\s*;$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
if [[ -n "$couch_nginx_working_dir" ]]; then [[ "$couch_nginx_working_dir" =~ ^/ ]] || couch_nginx_working_dir=$(nginx -V 2>&1 | grep -oP "\s--prefix=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--prefix=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")/"$couch_nginx_working_dir"; 
couch_nginx_user=$(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP '(\{|}|^|;)\s*user\s+\S+?(;|\s)' | tail -n 1 | sed -r 's/(\{|}|^|;)\s*user\s+//' | sed -r 's/\s*;?$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [[ -n "$couch_nginx_user" ]]; then couch_nginx_group=$(id -gn "$couch_nginx_user"); else couch_nginx_group="root"; fi; 
chmod o-rwx "$couch_nginx_working_dir"; chown root:"$couch_nginx_group" "$couch_nginx_working_dir"; 
fi


echo "[Manual]" 'If any ports are listening that are not authorized, comment out or delete the associated configuration for that listener.

Default: only port 80 is listening.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure your first server block mirrors the below in your nginx configuration, either at /etc/nginx/nginx.conf or any included file within your nginx config: 
server { 
return 404; 
} 
Then investigate each server block to ensure the server_name directive is explicitly defined. Each server block should look similar to the below with the defined hostname of the associated server block in the server_name directive. For example, if your server is example.org, the configuration should look like the below example: 
server { 
.....
server_name example.org; 
..... 
}

Default: no reject.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/^([^#]*[{};])?(\s*keepalive_timeout\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        keepalive_timeout 10;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*keepalive_timeout\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        keepalive_timeout 10;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*keepalive_timeout\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        keepalive_timeout 10;/' "$couch_conffile"; done


sed -ri 's/^([^#]*[{};])?(\s*send_timeout\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        send_timeout 10;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*send_timeout\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        send_timeout 10;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*send_timeout\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        send_timeout 10;/' "$couch_conffile"; done


sed -ri 's/^([^#]*[{};])?(\s*server_tokens\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        server_tokens off;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*server_tokens\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        server_tokens off;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*server_tokens\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        server_tokens off;/' "$couch_conffile"; done


nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*root\s+([^'\"]\S*|'.*?'|\".*?\")\s*;" | sed -r 's/(\{|}|^|;)\s*root\s+//' | sed -r 's/\s*;$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r each; do \
if [[ "$each" =~ ^/ ]]; then couch_nginx_web_root="$each"; else couch_nginx_web_root=$(nginx -V 2>&1 | grep -oP "\s--prefix=([^'\"]\S*|'.*?'|\".*?\")" | sed 's/\s--prefix=//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")/"$each"; fi; 
grep -i nginx "$couch_nginx_web_root"/404.html 2>/dev/null && echo '<strong>404 HTTP</strong>' > "$couch_nginx_web_root"/404.html || true; 
grep -i nginx "$couch_nginx_web_root"/50x.html 2>/dev/null && echo '<strong>404 HTTP</strong>' > "$couch_nginx_web_root"/50x.html || true; 
done


echo "[Manual]" 'Edit the nginx.conf file and add the following line: 
location ~ /\. { 
  deny all; 
  return 404; 
}

Note: This may break well-known hidden files that are needed for functionality. For example, it may prevent functionality used by LetsEncrypt. To enable, configure a location exception like that shown below: 
location ~ /\.well-known\/acme-challenge { 
 allow all; 
}

Default: not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Implement the below directives as part of your locations block which are used for proxing. Edit /etc/nginx/nginx.conf or included configuration files and add the following: 
location /docs { 
.... 
proxy_hide_header X-Powered-By; 
proxy_hide_header Server; 
.... 
}

Default: nginx does not pass the header fields “Date”, “Server”, “X-Pad”, and “X-Accel-...” from the response of a proxied server to a client.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit the log format directive in /etc/nginx/nginx.conf so it logs everything needed to meet your organizational policies. 
The following variables may be considered as useful examples include in your log_format with descriptive logging. You should consult the NGINX documentation and your organizational policy to ensure you are logging sufficient information and removing sensitive information where needed. 
$remote_addr - client address 
$remote_user - the user if basic authentication is used 
$status - the HTTP response status 
$content_type - Content-Type request header field 
$time_local - local time in the Common Log Format 
$request_method - request method, usually GET or POST 
$request - full original request line 
$uri - normalized URI in request 
$server_port - port of the server which accepted a request 
$server_name - name of the server which accepted a request 
$http_user_agent - user agent of the client requesting access 
$http_x_forwarded_for - client address a proxy or load balancer is forwarding traffic for

Default: log_format combined '\''$remote_addr - $remote_user [$time_local] '\''
                    '\''"$request" $status $body_bytes_sent '\''
                    '\''"$http_referer" "$http_user_agent"'\'';'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/^([^#]*[{};])?(\s*access_log\s+off(\s|;))/\1 ## \2/' "$nginx_main_conf_file"; 

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*access_log\s+off(\s|;))/\1 ## \2/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*access_log\s+off(\s|;))/\1 ## \2/' "$couch_conffile"; done


echo "[Manual]" 'Ensure that error logging is configured to correct level and location. The configuration should look similar to the below (configured to the logging location of your choice): 
error_log /var/log/nginx/error.log info;

Default: error_log logs/error.log error;.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Endure that log rotation if configured for nginx. Edit the /etc/logrotate.d/nginx file options if needed.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable central logging for your error logs, add the below line to your server block in your server configuration file. 192.168.2.1 should be replaced with the location of your central log server. 
error_log syslog:server=192.168.2.1 info;
OR sending logs to central server can be configured with syslog services. In such case exclude this check.

Default: not send.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable central logging for your access logs, add the below line to your server block in your server configuration file. 192.168.2.1 should be replaced with the location of your central log server. The local logging facility may be changed to any unconfigured facility on your server. 
access_log syslog:server=192.168.2.1,facility=local7,tag=nginx,severity=info combined;
OR sending logs to central server can be configured with syslog services. In such case exclude this check.

Default: not send.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To ensure your proxy or load balancer will forward information about the client and the proxy to the application, you must set one of the below headers in your location block. Edit your location block so it shows the proxy_set_header directives for the client and the proxy as shown below. These headers are the exact same and there is no need to have both present. 
server { 
... 
location / { 
proxy_pass (Insert Application URL here); 
proxy_set_header X-Real-IP $remote_addr; 
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 
} 
}

Default: not configured, not pass source IP information.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit your web server or proxy configuration file to redirect all unencrypted listening ports, such as port 80, using a redirection through the return directive: 
server { 
listen 80; 
server_name example.org; 
return 301 https://$host$request_uri; 
}

Default: NGINX is not configured to use HTTPS or redirect to it.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Use the following procedure to install a certificate and its signing certificate chain onto your web server, load balancer, or proxy. 
Step 1: Create the server'\''s private key and a certificate signing request. 
The following command will create your certificate'\''s private key with 2048-bit key strength. Optionally, this parameter may be changed to 4096 for greater security. It will also output your certificate signing request to the nginx.csr file in your present working directory. 
openssl req -new -newkey rsa:2048 -keyout nginx.key -out nginx.csr 
Enter the below information about your private key: 
Country Name (2 letter code) [XX]: Your Country 
State or Province Name (full name) []: Your State 
Locality Name (eg, city) [Default City]: Your City 
Organization Name (eg, company) [Default Company Ltd]: Your City 
Organizational Unit Name (eg, section) []: Your Organizational Unit 
Common Name (eg, your name or your server'\''s hostname) []: Your server'\''s DNS name 
Email Address []: Your email address 
Step 2: Obtain a signed certificate from your certificate authority. 
Provide your chosen certificate authority with your certificate signing request. Follow your certificate authority'\''s signing procedures in order to obtain a certificate and the certificate'\''s trust chain. A full trust chain is typically delivered in .pem format. 
Step 3: Install certificate and signing certificate chain on your web server. 
Place the .pem file from your certificate authority into the directory of your choice. Locate your created key file from the command you used to generate your certificate signing request. Open your website configuration file and edit your encrypted listener to leverage the ssl_certificate and ssl_certificate_key directives for a web server as shown below. You should also inspect include files inside your nginx.conf. This should be part of the server block. 
server { 
 listen 443 ssl http2; 
 listen [::]:443 ssl http2; 
 ssl_certificate /etc/nginx/cert.pem; 
 ssl_certificate_key /etc/nginx/nginx.key; 
... 
} 
After editing this file, you must recycle nginx services for these changes to take effect. This can be done with the following command: 
sudo service nginx restart

Default: no certificate is installed.'
read -n 1 -p "Press Enter to continue..."


nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*ssl_certificate_key\s+([^'\"]\S*|'.*?'|\".*?\")" | sed -r 's/(\{|}|^|;)\s*ssl_certificate_key\s+//' | sed -r 's/\s*;$//' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_nginx_key_file; do [[ "$couch_nginx_key_file" =~ ^/ ]] || couch_nginx_key_file=$(dirname "$nginx_main_conf_file")/"$couch_nginx_key_file"; chmod 400 "$couch_nginx_key_file" 2>&1; done


couch_tls_versions="TLSv1.2"
openssl version | grep -Ei '^openssl\s+([3-9]\.|1\.1\.1)' && couch_tls_versions="TLSv1.2 TLSv1.3"

sed -ri 's/^([^#]*[{};])?(\s*ssl_protocols\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_protocols '"${couch_tls_versions}"';/' "$nginx_main_conf_file";
sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_protocols\s)/\1 proxy_ssl_protocols '"${couch_tls_versions}"'; ## \2/' "$nginx_main_conf_file"; 

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_protocols\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_protocols "${couch_tls_versions}";/' $couch_conffile; sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_protocols\s)/\1 proxy_ssl_protocols "${couch_tls_versions}"; ## \2/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_protocols\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_protocols "${couch_tls_versions}";/' "$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_protocols\s)/\1 proxy_ssl_protocols "${couch_tls_versions}"; ## \2/' "$couch_conffile"; done


sed -ri 's/^([^#]*[{};])?(\s*ssl_ciphers\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;/' "$nginx_main_conf_file";
sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_ciphers\s)/\1 proxy_ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4; ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/^([^#]*[{};])?(\s*ssl_prefer_server_ciphers\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_prefer_server_ciphers on;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_ciphers\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;/' $couch_conffile; sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_ciphers\s)/\1 proxy_ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4; ## \2/' $couch_conffile; sed -ri 's/^([^#]*[{};])?(\s*ssl_prefer_server_ciphers\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_prefer_server_ciphers on;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_ciphers\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4;/' "$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*proxy_ssl_ciphers\s)/\1 proxy_ssl_ciphers ALL:!EXP:!NULL:!aNULL:!ADH:!AECDH:!LOW:!SSLv2:!SSLv3:!MD5:!RC4; ## \2/' "$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_prefer_server_ciphers\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_prefer_server_ciphers on;/' "$couch_conffile"; done


if [[ -z $(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -v '^\s*#' | grep -E '(\{|}|^|;)\s*ssl_dhparam\s+\S') ]]; then \
couch_dir=$(dirname "$nginx_main_conf_file"); mkdir "$couch_dir"/ssl; chown go-rwx "$couch_dir"/ssl; openssl dhparam -out "$couch_dir"/ssl/dhparam.pem 2048; chmod 400 "$couch_dir"/ssl/dhparam.pem; 

sed -ri "s:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        ssl_dhparam ${couch_dir}/ssl/dhparam.pem;:" "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        ssl_dhparam ${couch_dir}/ssl/dhparam.pem;:" $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        ssl_dhparam ${couch_dir}/ssl/dhparam.pem;:" "$couch_conffile"; done;

fi


sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling on;/' "$nginx_main_conf_file";
sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling_verify\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling_verify on;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling on;/' $couch_conffile; sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling_verify\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling_verify on;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling on;/' "$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_stapling_verify\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_stapling_verify on;/' "$couch_conffile"; done


echo "[Manual]" 'Ensure the below snippet of code can be found in each http or server block of nginx configuration. This will ensure the HSTS header is set with a validity period of six months, or 15768000 seconds. 
server { 
add_header Strict-Transport-Security "max-age=15768000;"; 
}

Default: HSTS headers are not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'This recommendation is for sites with enhanced security level and may be not applicable in other cases.
Note! Preloading should only be done with careful consideration! Your website and all its subdomains will be forced over HTTPS. If your website or any of its subdomains are not able to support preloading, you should not preload your site. Preloading should be opt-in only, and if done, may impact more sites than the nginx instance you are working on. Removing preloading can be slow and painful, and should only be done with careful consideration according to https://hstspreload.org.

In order to successfully preload your website, you must meet the below criteria: 
1: Serve a valid certificate. 
2: Redirect from HTTP to HTTPS if using not SSL/TLS port. 
3: Configure all subdomains to support HTTPS only. 
This will require you to configure all subdomains for HTTPS only. For example, a subdomain of example.org is workbench.example.org and would need to be configured for HTTPS only. 
4: Configure an HSTS header on your base domain, as shown below for nginx. 
If your base domain is nginx, you may accomplish this with several modifications from the HSTS recommendation. Change your header to include the preload directive and the includesubdomains directive, and make your max-length six months or longer. The header should be modified similar to the below snippet:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"; 
After you have met these requirements, add your site to the list by following the instructions at https://hstspreload.org/.

Default: website is not preloaded.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/^([^#]*[{};])?(\s*ssl_session_tickets\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_session_tickets off;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_session_tickets\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_session_tickets off;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*ssl_session_tickets\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        ssl_session_tickets off;/' "$couch_conffile"; done


echo "[Manual]" 'Open the nginx server configuration file and configure all listening ports with http2, similar to that of this example: 
server { 
listen 443 ssl http2; 
}

Default: HTTP/1.1 is used.

Note: Legacy user agents may not be able to connect to a server using HTTP/2.0.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Obtain the full certificate chain of the upstream server in .pem format. Then reference that file in the location block as part of the proxy_ssl_trusted_certificate directive. Implement the proxy_ssl_trusted_certificate and proxy_ssl_verify directives as shown below as part of the location block you are using to send traffic to your upstream server. 
proxy_ssl_trusted_certificate /etc/nginx/trusted_ca_cert.pem; 
proxy_ssl_verify on;

Default: proxy_ssl_verify off;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In order to implement this recommendation, you must create a client certificate to be authenticated against and have it signed. Once you have a signed certificate, place the certificate in a location of your choice. In the below example, we use /etc/nginx/ssl/cert.pem. Implement the configuration as part of the location block that is sending traffic to an upstream location: 
proxy_ssl_certificate /etc/nginx/ssl/nginx.pem; 
proxy_ssl_certificate_key /etc/nginx/ssl/nginx.key;

Default: not authenticated.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Compile a list of network ranges or IP addresses you would want to access your web server or proxy. Then add these ranges with the allow directive. The deny directive should be included with all IP addresses implicitly denied. 
location / { 
allow 10.1.1.1; 
deny all; 
}

Default: no restrictions for IP addresses.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remove unneeded methods and only allow required methods, add the following into every server block in your nginx.conf. The below snippet assumes only the methods GET, HEAD and POST are required for an application. The reason for 444 as a response is because it contains no information and can help mitigate automated attacks. 
if ($request_method !~ ^(GET|HEAD|POST)$) { 
return 444; 
}

Default: All methods are allowed.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/^([^#]*[{};])?(\s*client_body_timeout\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_body_timeout 10;/' "$nginx_main_conf_file";
sed -ri 's/^([^#]*[{};])?(\s*client_header_timeout\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_header_timeout 10;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*client_body_timeout\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_body_timeout 10;/' $couch_conffile; sed -ri 's/^([^#]*[{};])?(\s*client_header_timeout\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_header_timeout 10;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*client_body_timeout\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_body_timeout 10;/' "$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*client_header_timeout\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_header_timeout 10;/' "$couch_conffile"; done


sed -ri 's/^([^#]*[{};])?(\s*client_max_body_size\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_max_body_size 100K;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*client_max_body_size\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_max_body_size 100K;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*client_max_body_size\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        client_max_body_size 100K;/' "$couch_conffile"; done


sed -ri 's/^([^#]*[{};])?(\s*large_client_header_buffers\s)/\1 ## \2/' "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        large_client_header_buffers 2 1k;/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*large_client_header_buffers\s)/\1 ## \2/' $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        large_client_header_buffers 2 1k;/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/^([^#]*[{};])?(\s*large_client_header_buffers\s)/\1 ## \2/' "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        large_client_header_buffers 2 1k;/' "$couch_conffile"; done


echo "[Manual]" 'Implement the below directives under the HTTP and server blocks of your nginx configuration or any include files. The below configuration creates a memory zone of 10 megabytes called limitperip (you can set this to whatever name you wish). It will limit the number of connections per IP address to 30 simultaneous connections. The number of simultaneous connections to allow may be different depending on your organization'\''s policies and use cases. 
http { 
 limit_conn_zone $binary_remote_addr zone=limitperip:10m; 
 server { 
  limit_conn limitperip 30; 
 } 
}

Default: not restricted.

Note! Users of your system that are behind a corporate web proxy using network address translation or a proxy service such as tor may have an increased chance of being blocked due to this configuration. This is because multiple users in these scenarios come from the same IP address. You should always consider your user base when setting a connection limit.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Implement the below directives under the HTTP and server blocks of your nginx configuration or any include files. The below configuration creates a memory zone of 10 megabytes called "ratelimit" (you can set this to whatever name you wish) and sets the number of requests per second that can be sent by any given IP address to 5. Further, this configuration sets a burst of 10 to ensure that requests may come more frequently and sets no delay to ensure that the bursting may be all at once and not queued. 
http { 
 limit_req_zone $binary_remote_addr zone=ratelimit:10m rate=5r/s; 
 server { 
  limit_req zone=ratelimit burst=10 nodelay; 
 } 
}

Default: not restricted.

Note! If you serve a high traffic API, this may prevent users from being able to call your website. You may also limit users behind a corporate web proxy or a proxy service such as tor if they use your website heavily.'
read -n 1 -p "Press Enter to continue..."


sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Frame-Options[\"']?\s)/\1 ## \2/" "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Frame-Options "SAMEORIGIN";/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Frame-Options[\"']?\s)/\1 ## \2/" $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Frame-Options "SAMEORIGIN";/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Frame-Options[\"']?\s)/\1 ## \2/" "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Frame-Options "SAMEORIGIN";/' "$couch_conffile"; done


sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Content-Type-Options[\"']?\s)/\1 ## \2/" "$nginx_main_conf_file"; 
sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Content-Type-Options "nosniff";/' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Content-Type-Options[\"']?\s)/\1 ## \2/" $couch_conffile; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Content-Type-Options "nosniff";/' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?X-Content-Type-Options[\"']?\s)/\1 ## \2/" "$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        add_header X-Content-Type-Options "nosniff";/' "$couch_conffile"; done


echo "[Manual]" 'Open your nginx configuration file that contains your server blocks. Add the Content-Security-Policy header into every http or server block and direct your user agent to accept documents from only specific origins. The Content-Security-Policy directives can be configured as needed, but without '\''unsafe-eval'\'' and '\''unsafe-inline'\'' keywords. Example:
add_header Content-Security-Policy "default-src '\''self'\''";

Default: no Content-Security-Policy header.'
read -n 1 -p "Press Enter to continue..."


sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?Referrer-Policy[\"']?\s+[\"']?[^\"'#]*unsafe-url)/\1 ## \2/" "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?Referrer-Policy[\"']?\s+[\"']?[^\"'#]*unsafe-url)/\1 ## \2/" $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri "s/^([^#]*[{};])?(\s*add_header\s+[\"']?Referrer-Policy[\"']?\s+[\"']?[^\"'#]*unsafe-url)/\1 ## \2/" "$couch_conffile"; done

if [[ -z $(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -v '^\s*#' | grep -Ei '(\{|}|^|;)\s*add_header\s+[\"']?Referrer-Policy[\"']?\s') ]]; then \

sed -ri 's:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        add_header Referrer-Policy "strict-origin-when-cross-origin";:' "$nginx_main_conf_file";

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        add_header Referrer-Policy "strict-origin-when-cross-origin";:' $couch_conffile; done

nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's:(^([^#]*[{};])?\s*server\s*\{.*$):\1\n        add_header Referrer-Policy "strict-origin-when-cross-origin";:' "$couch_conffile"; done;

fi


if [[ -z $(nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*map\s+\\\$http_user_agent\s+\\\$blockedagent\s*{") ]]; then \
  printf "map \$http_user_agent \$blockedagent {\ndefault         0;\n~*malicious     1;\n~*bot           1;\n~*backdoor      1;\n~*crawler       1;\n~*bandit        1;\n}\n" > "$(dirname "$nginx_main_conf_file")/blockuseragents.rules"; 
  chmod go-rwx "$(dirname "$nginx_main_conf_file")/blockuseragents.rules";
  sed -ri '0,/^([^#]*[{};])?\s*http\s*\{/s/(^([^#]*[{};])?\s*http\s*\{.*$)/&\n  include blockuseragents.rules;/' "$nginx_main_conf_file";

  sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        if ($blockedagent) {\n          return 403;\n        }/' "$nginx_main_conf_file";

  nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)" | sed -r "s/(\{|}|^|;)\s*include\s+([^'\"]\S*)(\s|;|$)/\2/" | sed -e "s/;$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        if ($blockedagent) {\n          return 403;\n        }/' $couch_conffile; done;

  nginx -T -c "$nginx_main_conf_file" 2>/dev/null | grep -oP "(\{|}|^|;)\s*include\s+('.*?'|\".*?\")" | sed -r "s/(\{|}|^|;)\s*include\s+('.*?'|\".*?\")/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | while read -r couch_conffile; do [[ "$couch_conffile" =~ ^/ ]] || couch_conffile=$(dirname "$nginx_main_conf_file")/"$couch_conffile"; sed -ri 's/(^([^#]*[{};])?\s*server\s*\{.*$)/\1\n        if ($blockedagent) {\n          return 403;\n        }/' "$couch_conffile"; done; 
fi


echo "[Manual]" 'For example, let’s say you have a subdirectory named img inside your server block where you store all the images used in that virtual host. To prevent other sites from using your images, you will need to insert the following location block inside your virtual host definition:

location /img/ {
valid_referers none blocked 192.168.0.25;
if ($invalid_referer) {
return   403;
}
}
Then modify the index.html file in each virtual host as follows:
Example for another hosts that valid hosts:
<!DOCTYPE html>
<html>
...
<img src=”http://192.168.0.25/img/nginx.png” />
...
</html> 
Example for valid hosts: 
<!DOCTYPE html>
<html>
...
<img src=”img/nginx.png” />
...
</html>'
read -n 1 -p "Press Enter to continue..."



