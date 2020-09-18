#!/bin/bash
################################################################################
# Original Author:   crombiecrunch
# Modified by : Xavatar (https://github.com/xavatar/yiimp_install_scrypt)
# Web: https://www.xavatar.com    
# This version Modified by : Synergy Technology Consultancy Services 
# (https://github.com/synergytcs/yiimp_install_scrypt)
# Web: https://pool.baddcoin.org    
# Program:
#   Install yiimp on Ubuntu 16.04/18.04 running Nginx, MariaDB, and php7.3
#   Based on Xavatar v0.2 (update Avril, 2020) (with kudos)
#   This version 1.1
################################################################################
    

    output() {
    printf "\E[0;33;40m"
    echo $1
    printf "\E[0m"
    }

    displayErr() {
    echo
    echo $1;
    echo
    exit 1;
    }

    #Add user group sudo + no password
    whoami=`whoami`
    sudo usermod -aG sudo ${whoami}
    echo '# yiimp
    # It needs passwordless sudo functionality.
    '""''"${whoami}"''""' ALL=(ALL) NOPASSWD:ALL
    ' | sudo -E tee /etc/sudoers.d/${whoami} >/dev/null 2>&1
    
    #Copy needed files
    sudo cp -r conf/functions.sh /etc/
    sudo cp -r utils/screen-scrypt.sh /etc/
    sudo cp -r conf/editconf.py /usr/bin/
    sudo chmod +x /usr/bin/editconf.py
    sudo chmod +x /etc/screen-scrypt.sh

    source /etc/functions.sh


    clear
    echo
    echo -e "$GREEN************************************************************************$COL_RESET"
    echo -e "$GREEN Yiimp Install Script v1.1 $COL_RESET"
    echo -e "$GREEN Install yiimp on Ubuntu 18.04 running Nginx, MariaDB, and php7.3 $COL_RESET"
    echo -e "$GREEN************************************************************************$COL_RESET"
    echo
    sleep 3


    #make post install script writeable
    sudo chmod +x POST-install-fixes.sh
    
    # Update package and Upgrade Ubuntu
    echo
    echo
    echo -e "$CYAN => Updating system and installing required packages :$COL_RESET"
    echo 
    sleep 3
        
    sudo apt -y update 
    sudo apt -y upgrade
    sudo apt -y autoremove
    sudo apt -y install dialog python3 python3-pip acl nano apt-transport-https
    echo -e "$GREEN Done...$COL_RESET"


    source conf/prerequisite.sh
    sleep 3
    source conf/getip.sh


    echo 'PUBLIC_IP='"${PUBLIC_IP}"'
    PUBLIC_IPV6='"${PUBLIC_IPV6}"'
    DISTRO='"${DISTRO}"'
    PRIVATE_IP='"${PRIVATE_IP}"'' | sudo -E tee conf/pool.conf >/dev/null 2>&1

    echo
    echo
    echo -e "$RED Make sure you double check before hitting enter! Only one shot at these! $COL_RESET"
    echo
    #read -e -p "Enter time zone (e.g. America/New_York) : " TIME
    read -e -p "Domain Name (no http:// no www. just : example.com or pool.example.com or 185.22.24.26) : " server_name
    read -e -p "Are you using a subdomain (mycryptopool.example.com?) [y/N] : " sub_domain
    read -e -p "Enter support email (e.g. admin@example.com) : " EMAIL
    read -e -p "Set Pool to AutoExchange? i.e. mine any coin with BTC address? [y/N] : " BTC
    #read -e -p "Please enter a new location for /site/adminRights this is to customize the Admin Panel entrance url (e.g. myAdminpanel) : " admin_panel
    read -e -p "Enter the Public IP of the system you will use to access the admin panel (http://www.whatsmyip.org/) : " Public
    read -e -p "Install Fail2ban? [Y/n] : " install_fail2ban
    read -e -p "Install UFW and configure ports? [Y/n] : " UFW
    read -e -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " ssl_install
    read -e -p "Remove default coins? [Y/n] : " rem_coins
    
    
    # Switch Aptitude
    #echo
    #echo -e "$CYAN Switching to Aptitude $COL_RESET"
    #echo 
    #sleep 3
    #sudo apt -y install aptitude
    #echo -e "$GREEN Done...$COL_RESET $COL_RESET"


    # Installing Nginx
    echo
    echo
    echo -e "$CYAN => Installing Nginx server : $COL_RESET"
    echo
    sleep 3
    
    if [ -f /usr/sbin/apache2 ]; then
    echo -e "Removing apache..."
    apt-get -y purge apache2 apache2-*
    apt-get -y --purge autoremove
    fi

    sudo apt -y install nginx
    sudo rm /etc/nginx/sites-enabled/default
    sudo systemctl start nginx.service
    sudo systemctl enable nginx.service
    sudo systemctl start cron.service
    sudo systemctl enable cron.service
    sleep 5
    sudo systemctl status nginx | sed -n "1,3p"
    sleep 15
    echo
    echo -e "$GREEN Done...$COL_RESET"
    

    # Making Nginx a bit hard
    echo 'map $http_user_agent $blockedagent {
    default         0;
    ~*malicious     1;
    ~*bot           1;
    ~*backdoor      1;
    ~*crawler       1;
    ~*bandit        1;
    }
    ' | sudo -E tee /etc/nginx/blockuseragents.rules >/dev/null 2>&1
    
    
    # Installing Mariadb
    echo
    echo
    echo -e "$CYAN => Installing Mariadb Server : $COL_RESET"
    echo
    sleep 3
        
    # Create random password
    rootpasswd=$(openssl rand -base64 12)
    export DEBIAN_FRONTEND="noninteractive"
    sudo apt -y install mariadb-server
    sudo systemctl start mysql
    sudo systemctl enable mysql
    sleep 5
    sudo systemctl status mysql | sed -n "1,3p"
    sleep 15
    echo
    echo -e "$GREEN Done...$COL_RESET"

    
    # Installing Installing php7.3
    echo
    echo
    echo -e "$CYAN => Installing php7.3 : $COL_RESET"
    echo
    sleep 3
    
    source conf/pool.conf
    if [ ! -f /etc/apt/sources.list.d/ondrej-php-bionic.list ]; then
    sudo add-apt-repository -y ppa:ondrej/php
    fi
    sudo apt -y update

    if [[ ("$DISTRO" == "16") ]]; then
    sudo apt -y install php7.3-fpm php7.3-opcache php7.3 php7.3-common php7.3-gd php7.3-mysql php7.3-imap php7.3-cli \
    php7.3-cgi php-pear php-auth imagemagick libruby php7.3-curl php7.3-intl php7.3-pspell mcrypt\
    php7.3-recode php7.3-sqlite3 php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php-memcache php-imagick php-gettext php7.3-zip php7.3-mbstring
    #sudo phpenmod mcrypt
    #sudo phpenmod mbstring
    else
    sudo apt -y install php7.3-fpm php7.3-opcache php7.3 php7.3-common php7.3-gd php7.3-mysql php7.3-imap php7.3-cli \
    php7.3-cgi php-pear imagemagick libruby php7.3-curl php7.3-intl php7.3-pspell mcrypt\
    php7.3-recode php7.3-sqlite3 php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php-memcache php-imagick php-gettext php7.3-zip php7.3-mbstring \
    libpsl-dev libnghttp2-dev
    fi
    sleep 5
    sudo systemctl start php7.3-fpm
    sudo systemctl status php7.3-fpm | sed -n "1,3p"
    sleep 15
    echo
    echo -e "$GREEN Done...$COL_RESET"

    
    # Installing other needed files
    echo
    echo
    echo -e "$CYAN => Installing other needed files : $COL_RESET"
    echo
    sleep 3
    
    sudo apt -y install libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev libkrb5-dev libldap2-dev libidn11-dev gnutls-dev \
    librtmp-dev sendmail mutt screen git
    sudo apt -y install pwgen -y
    echo -e "$GREEN Done...$COL_RESET"
    sleep 3

    
    # Installing Package to compile crypto currency
    echo
    echo
    echo -e "$CYAN => Installing Package to compile crypto currency $COL_RESET"
    echo
    sleep 3
    
    sudo apt -y install software-properties-common build-essential
    sudo apt -y install libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils git cmake libboost-all-dev zlib1g-dev libz-dev libseccomp-dev libcap-dev libminiupnpc-dev gettext
    sudo apt -y install libminiupnpc10 libzmq5
    sudo apt -y install libcanberra-gtk-module libqrencode-dev libzmq3-dev
    sudo apt -y install libqt5gui5 libqt5core5a libqt5webkit5-dev libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler
    sudo add-apt-repository -y ppa:bitcoin/bitcoin
    sudo apt -y update
    sudo apt -y install libdb4.8-dev libdb4.8++-dev libdb5.3 libdb5.3++
    echo -e "$GREEN Done...$COL_RESET"
       
    
    # Generating Random Passwords
    password=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    password2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    AUTOGENERATED_PASS=`pwgen -c -1 20`
    
    
    # Test Email
    echo
    echo
    echo -e "$CYAN => Testing to see if server emails are sent $COL_RESET"
    echo
    sleep 3
    
    if [[ "$root_email" != "" ]]; then
        echo $root_email > sudo tee --append ~/.email
        echo $root_email > sudo tee --append ~/.forward

    if [[ ("$send_email" == "y" || "$send_email" == "Y" || "$send_email" == "") ]]; then
        echo "This is a mail test for the SMTP Service." > sudo tee --append /tmp/email.message
        echo "You should receive this !" >> sudo tee --append /tmp/email.message
        echo "" >> sudo tee --append /tmp/email.message
        echo "Cheers" >> sudo tee --append /tmp/email.message
        sudo sendmail -s "SMTP Testing" $root_email < sudo tee --append /tmp/email.message

        sudo rm -f /tmp/email.message
        echo "Mail sent"
    fi
    fi
    echo -e "$GREEN Done...$COL_RESET"
    
    # Installing Fail2Ban & UFW
    echo
    echo
    echo -e "$CYAN => Some optional installs (Fail2Ban & UFW) $COL_RESET"
    echo
    sleep 3
    
    
    if [[ ("$install_fail2ban" == "y" || "$install_fail2ban" == "Y" || "$install_fail2ban" == "") ]]; then
    sudo apt -y install fail2ban
    sleep 5
    sudo systemctl status fail2ban | sed -n "1,3p"
        fi


    if [[ ("$UFW" == "y" || "$UFW" == "Y" || "$UFW" == "") ]]; then
    sudo apt -y install ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
    sudo ufw allow 3333/tcp    
    sudo ufw --force enable
    sleep 5
    sudo systemctl status ufw | sed -n "1,3p"   
    fi

    
    echo
    echo -e "$GREEN Done...$COL_RESET"

    
    # Installing PhpMyAdmin
    echo
    echo
    echo -e "$CYAN => Installing phpMyAdmin $COL_RESET"
    echo
    sleep 3
    
    echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/admin-user string root" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/admin-pass password $rootpasswd" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/app-pass password $AUTOGENERATED_PASS" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/app-password-confirm password $AUTOGENERATED_PASS" | sudo debconf-set-selections
    sudo apt -y install phpmyadmin
    echo -e "$GREEN Done...$COL_RESET"
    
    
    # Installing Yiimp
    echo
    echo
    echo -e "$CYAN => Installing Yiimp $COL_RESET"
    echo
    echo -e "Grabbing yiimp fron Github, building files and setting file structure."
    echo
    sleep 3
    

    # Generating Random Password for stratum
    blckntifypass=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    
    # Compil Blocknotify
    cd ~
    git clone https://github.com/tpruvot/yiimp
    cd $HOME/yiimp/blocknotify
    sudo sed -i 's/tu8tu5/'$blckntifypass'/' blocknotify.cpp
    sudo make
    
    # Compil iniparser
    cd $HOME/yiimp/stratum/iniparser
    sudo make
    
    # Compil Stratum
    cd $HOME/yiimp/stratum
    if [[ ("$BTC" == "y" || "$BTC" == "Y") ]]; then
    sudo sed -i 's/CFLAGS += -DNO_EXCHANGE/#CFLAGS += -DNO_EXCHANGE/' $HOME/yiimp/stratum/Makefile
    fi
    sudo make
    
    # Copy Files (Blocknotify,iniparser,Stratum)
    cd $HOME/yiimp
    sudo sed -i 's/AdminRights/'AdminPanel'/' $HOME/yiimp/web/yaamp/modules/site/SiteController.php
    sudo cp -r $HOME/yiimp/web /var/
    sudo mkdir -p /var/stratum
    cd $HOME/yiimp/stratum
    sudo cp -a config.sample/. /var/stratum/config
    sudo cp -r stratum /var/stratum
    sudo cp -r run.sh /var/stratum
    cd $HOME/yiimp
    sudo cp -r $HOME/yiimp/bin/. /bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /usr/bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /var/stratum/
    sudo mkdir -p /etc/yiimp
    sudo mkdir -p /$HOME/backup/
    #fixing yiimp
    sudo sed -i "s|ROOTDIR=/data/yiimp|ROOTDIR=/var|g" /bin/yiimp
    #fixing run.sh
    sudo rm -r /var/stratum/config/run.sh
    echo '
    #!/bin/bash
    ulimit -n 10240
    ulimit -u 10240
    cd /var/stratum
    while true; do
    ./stratum /var/stratum/config/$1
    sleep 2
    done
    exec bash
    ' | sudo -E tee /var/stratum/config/run.sh >/dev/null 2>&1
    sudo chmod +x /var/stratum/config/run.sh

    echo -e "$GREEN Done...$COL_RESET"


    # Update Timezone
    echo
    echo
    echo -e "$CYAN => Update default timezone. $COL_RESET"
    echo
    
    echo -e " Setting TimeZone to UTC...$COL_RESET"
    if [ ! -f /etc/timezone ]; then
    echo "Setting timezone to UTC."
    echo "Etc/UTC" > sudo /etc/timezone
    sudo systemctl restart rsyslog
    fi
    sudo systemctl status rsyslog | sed -n "1,3p"
    echo
    echo -e "$GREEN Done...$COL_RESET"
    
    
    # Creating webserver initial config file
    echo
    echo
    echo -e "$CYAN => Creating webserver initial config file $COL_RESET"
    echo
    
    # Adding user to group, creating dir structure, setting permissions
    sudo mkdir -p /var/www/$server_name/html

    if [[ ("$sub_domain" == "y" || "$sub_domain" == "Y") ]]; then
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log /var/log/nginx/'"${server_name}"'.app-access.log;
        error_log /var/log/nginx/'"${server_name}"'.app-error.log;
    
        # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
        try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        location ~ /\.ht {
        deny all;
        }
        location ~ /.well-known {
        allow all;
        }
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
      }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    sudo systemctl reload php7.3-fpm.service
    sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"
        
    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

    
    # Install SSL (with SubDomain)
    echo
    echo -e "Install LetsEncrypt and setting SSL (with SubDomain)"
    echo
    
    sudo apt -y install letsencrypt
    sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name"
    sudo rm /etc/nginx/sites-available/$server_name.conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        # enforce https
        return 301 https://$server_name$request_uri;
    }
    
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"';
        
            root /var/www/'"${server_name}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${server_name}"'.app-access.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log;
        
            # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
            try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
       }
     }
    }
        
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1
    fi
    
    sudo systemctl reload php7.3-fpm.service
    sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"
    
    
    else
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log /var/log/nginx/'"${server_name}"'.app-access.log;
        error_log /var/log/nginx/'"${server_name}"'.app-error.log;
    
        # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
        try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        location ~ /\.ht {
        deny all;
        }
        location ~ /.well-known {
        allow all;
        }
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    sudo systemctl reload php7.3-fpm.service
    sudo systemctl restart nginx.service
    echo -e "$GREEN Done...$COL_RESET"
   
    
    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then
    
    # Install SSL (without SubDomain)
    echo
    echo -e "Install LetsEncrypt and setting SSL (without SubDomain)"
    echo
    sleep 3
    
    sudo apt -y install letsencrypt
    sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name" -d www."$server_name"
    sudo rm /etc/nginx/sites-available/$server_name.conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    echo 'include /etc/nginx/blockuseragents.rules;
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        # enforce https
        return 301 https://$server_name$request_uri;
    }
    
    server {
    if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"' www.'"${server_name}"';
        
            root /var/www/'"${server_name}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${server_name}"'.app-access.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log;
        
            # allow larger file uploads and longer script runtimes
    client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
            try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
            return 404;
        }
        location ~ \.sh {
        return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
        location /phpmyadmin {
        root /usr/share/;
        index index.php;
        try_files $uri $uri/ =404;
        location ~ ^/phpmyadmin/(doc|sql|setup)/ {
            deny all;
    }
        location ~ /phpmyadmin/(.+\.php)$ {
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }
      }
    }
        
    ' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    echo -e "$GREEN Done...$COL_RESET"

    fi
    sudo systemctl reload php7.3-fpm.service
    sudo systemctl restart nginx.service
    fi
    
    
    # Config Database
    echo
    echo
    echo -e "$CYAN => Now for the database fun! $COL_RESET"
    echo
    sleep 3
    
    # Create database
    Q1="CREATE DATABASE IF NOT EXISTS yiimpfrontend;"
    Q2="GRANT ALL ON *.* TO 'panel'@'localhost' IDENTIFIED BY '$password';"
    Q3="FLUSH PRIVILEGES;"
    SQL="${Q1}${Q2}${Q3}"
    sudo mysql -u root -p="" -e "$SQL"
    
    # Create stratum user
    Q1="GRANT ALL ON *.* TO 'stratum'@'localhost' IDENTIFIED BY '$password2';"
    Q2="FLUSH PRIVILEGES;"
    SQL="${Q1}${Q2}"
    sudo mysql -u root -p="" -e "$SQL"  
    
    #Create my.cnf
    
    echo '
    [clienthost1]
    user=panel
    password='"${password}"'
    database=yiimpfrontend
    host=localhost
    [clienthost2]
    user=stratum
    password='"${password2}"'
    database=yiimpfrontend
    host=localhost
    [myphpadmin]
    user=phpmyadmin
    password='"${AUTOGENERATED_PASS}"'
    [mysql]
    user=root
    password='"${rootpasswd}"'
    ' | sudo -E tee ~/.my.cnf >/dev/null 2>&1
      sudo chmod 0600 ~/.my.cnf


    # Create keys file
    echo '  
    <?php
    /* Sample config file to put in /etc/yiimp/keys.php */
    define('"'"'YIIMP_MYSQLDUMP_USER'"'"', '"'"'panel'"'"');
    define('"'"'YIIMP_MYSQLDUMP_PASS'"'"', '"'"''"${password}"''"'"');
    define('"'"'YIIMP_MYSQLDUMP_PATH'"'"', '"'"''"/var/yiimp/sauv"''"'"');
    /* Keys required to create/cancel orders and access your balances/deposit addresses */
    define('"'"'EXCH_BITTREX_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_BITSTAMP_SECRET'"'"','"'"''"'"');
    define('"'"'EXCH_BLEUTRADE_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_BTER_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_CCEX_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_COINMARKETS_PASS'"'"', '"'"''"'"');
    define('"'"'EXCH_CRYPTOPIA_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_EMPOEX_SECKEY'"'"', '"'"''"'"');
    define('"'"'EXCH_HITBTC_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_KRAKEN_SECRET'"'"','"'"''"'"');
    define('"'"'EXCH_LIVECOIN_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_NOVA_SECRET'"'"','"'"''"'"');
    define('"'"'EXCH_POLONIEX_SECRET'"'"', '"'"''"'"');
    define('"'"'EXCH_YOBIT_SECRET'"'"', '"'"''"'"');
    ' | sudo -E tee /etc/yiimp/keys.php >/dev/null 2>&1

    echo -e "$GREEN Done...$COL_RESET"

 
    # Peforming the SQL import
    echo
    echo
    echo -e "$CYAN => Database 'yiimpfrontend' and users 'panel' and 'stratum' created with password $password and $password2, will be saved for you $COL_RESET"
    echo
    echo -e "Performing the SQL import"
    echo
    sleep 3
    
    cd ~
    cd yiimp/sql
    
    # Import sql dump
    sudo zcat 2016-04-03-yaamp.sql.gz | sudo mysql --defaults-group-suffix=host1
    
    # Oh the humanity!
    sudo mysql --defaults-group-suffix=host1 --force < 2016-04-24-market_history.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-04-27-settings.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-11-coins.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-15-benchmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-23-bookmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-06-01-notifications.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-06-04-bench_chips.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-11-23-coins.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-02-05-benchmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-03-31-earnings_index.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-05-accounts_case_swaptime.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-06-payouts_coinid_memo.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-09-notifications.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-10-bookmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-11-segwit.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2018-01-stratums_ports.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2018-02-coins_getinfo.sql
    echo -e "$GREEN Done...$COL_RESET"
        
    
    # Generating a basic Yiimp serverconfig.php
    echo
    echo
    echo -e "$CYAN => Generating a basic Yiimp serverconfig.php $COL_RESET"
    echo
    sleep 3
    
    # Make config file
    echo '
    <?php

    ini_set('"'"'date.timezone'"'"', '"'"'UTC'"'"');

    define('"'"'YAAMP_LOGS'"'"', '"'"'/var/log/yiimp'"'"');
    define('"'"'YAAMP_HTDOCS'"'"', '"'"'/var/web'"'"');
        
    define('"'"'YAAMP_BIN'"'"', '"'"'/var/bin'"'"');
    
    define('"'"'YAAMP_DBHOST'"'"', '"'"'localhost'"'"');
    define('"'"'YAAMP_DBNAME'"'"', '"'"'yiimpfrontend'"'"');
    define('"'"'YAAMP_DBUSER'"'"', '"'"'panel'"'"');
    define('"'"'YAAMP_DBPASSWORD'"'"', '"'"''"${password}"''"'"');
    
    define('"'"'YAAMP_PRODUCTION'"'"', true);
    define('"'"'YAAMP_RENTAL'"'"', false);
    
    define('"'"'YAAMP_LIMIT_ESTIMATE'"'"', false);
    
    define('"'"'YAAMP_FEES_MINING'"'"', 0.5);
    define('"'"'YAAMP_FEES_EXCHANGE'"'"', 2);
    define('"'"'YAAMP_FEES_RENTING'"'"', 2);
    define('"'"'YAAMP_TXFEE_RENTING_WD'"'"', 0.002);
    
    define('"'"'YAAMP_PAYMENTS_FREQ'"'"', 2*60*60);
    define('"'"'YAAMP_PAYMENTS_MINI'"'"', 0.001);
    
    define('"'"'YAAMP_ALLOW_EXCHANGE'"'"', false);
    define('"'"'YIIMP_PUBLIC_EXPLORER'"'"', true);
    define('"'"'YIIMP_PUBLIC_BENCHMARK'"'"', false);
    
    define('"'"'YIIMP_FIAT_ALTERNATIVE'"'"', '"'"'USD'"'"'); // USD is main
    define('"'"'YAAMP_USE_NICEHASH_API'"'"', false);
    
    define('"'"'YAAMP_BTCADDRESS'"'"', '"'"'1C1hnjk3WhuAvUN6Ny6LTxPD3rwSZwapW7'"'"');
    
    define('"'"'YAAMP_SITE_URL'"'"', '"'"''"${server_name}"''"'"');
    define('"'"'YAAMP_STRATUM_URL'"'"', YAAMP_SITE_URL); // change if your stratum server is on a different host
    define('"'"'YAAMP_SITE_NAME'"'"', '"'"'YIIMP'"'"');
    define('"'"'YAAMP_ADMIN_EMAIL'"'"', '"'"''"${EMAIL}"''"'"');
    define('"'"'YAAMP_ADMIN_IP'"'"', '"'"''"${Public}"''"'"'); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
    
    define('"'"'YAAMP_ADMIN_WEBCONSOLE'"'"', true);
    define('"'"'YAAMP_CREATE_NEW_COINS'"'"', false);
    define('"'"'YAAMP_NOTIFY_NEW_COINS'"'"', false);
    
    define('"'"'YAAMP_DEFAULT_ALGO'"'"', '"'"'x11'"'"');
    
    define('"'"'YAAMP_USE_NGINX'"'"', true);
    
    // Exchange public keys (private keys are in a separate config file)
    define('"'"'EXCH_CRYPTOPIA_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_POLONIEX_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_BITTREX_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_BLEUTRADE_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_BTER_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_YOBIT_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_CCEX_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_COINMARKETS_USER'"'"', '"'"''"'"');
    define('"'"'EXCH_COINMARKETS_PIN'"'"', '"'"''"'"');
    define('"'"'EXCH_BITSTAMP_ID'"'"','"'"''"'"');
    define('"'"'EXCH_BITSTAMP_KEY'"'"','"'"''"'"');
    define('"'"'EXCH_HITBTC_KEY'"'"','"'"''"'"');
    define('"'"'EXCH_KRAKEN_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_LIVECOIN_KEY'"'"', '"'"''"'"');
    define('"'"'EXCH_NOVA_KEY'"'"', '"'"''"'"');
    
    // Automatic withdraw to Yaamp btc wallet if btc balance > 0.3
    define('"'"'EXCH_AUTO_WITHDRAW'"'"', 0.3);
    
    // nicehash keys deposit account & amount to deposit at a time
    define('"'"'NICEHASH_API_KEY'"'"','"'"'f96c65a7-3d2f-4f3a-815c-cacf00674396'"'"');
    define('"'"'NICEHASH_API_ID'"'"','"'"'825979'"'"');
    define('"'"'NICEHASH_DEPOSIT'"'"','"'"'3ABoqBjeorjzbyHmGMppM62YLssUgJhtuf'"'"');
    define('"'"'NICEHASH_DEPOSIT_AMOUNT'"'"','"'"'0.01'"'"');
    
    $cold_wallet_table = array(
    '"'"'1PqjApUdjwU9k4v1RDWf6XveARyEXaiGUz'"'"' => 0.10,
    );
    
    // Sample fixed pool fees
    $configFixedPoolFees = array(
        '"'"'zr5'"'"' => 2.0,
        '"'"'scrypt'"'"' => 20.0,
        '"'"'sha256'"'"' => 5.0,
     );
    
    // Sample custom stratum ports
    $configCustomPorts = array(
    //  '"'"'x11'"'"' => 7000,
    );
    
    // mBTC Coefs per algo (default is 1.0)
    $configAlgoNormCoef = array(
    //  '"'"'x11'"'"' => 5.0,
    );
    ' | sudo -E tee /var/web/serverconfig.php >/dev/null 2>&1

    echo -e "$GREEN Done...$COL_RESET"


    # Updating stratum config files with database connection info
    echo
    echo
    echo -e "$CYAN => Updating stratum config files with database connection info. $COL_RESET"
    echo
    sleep 3
 
    cd /var/stratum/config
    sudo sed -i 's/password = tu8tu5/password = '$blckntifypass'/g' *.conf
    sudo sed -i 's/server = yaamp.com/server = '$server_name'/g' *.conf
    sudo sed -i 's/host = yaampdb/host = localhost/g' *.conf
    sudo sed -i 's/database = yaamp/database = yiimpfrontend/g' *.conf
    sudo sed -i 's/username = root/username = stratum/g' *.conf
    sudo sed -i 's/password = patofpaq/password = '$password2'/g' *.conf
    cd ~
    echo -e "$GREEN Done...$COL_RESET"


    # Final Directory permissions
    echo
    echo
    echo -e "$CYAN => Final Directory permissions $COL_RESET"
    echo
    sleep 3

    whoami=`whoami`
    sudo usermod -aG www-data $whoami
    sudo usermod -a -G www-data $whoami

    sudo find /var/web -type d -exec chmod 775 {} +
    sudo find /var/web -type f -exec chmod 664 {} +
    sudo chgrp www-data /var/web -R
    sudo chmod g+w /var/web -R
    
    sudo mkdir /var/log/yiimp
    sudo touch /var/log/yiimp/debug.log
    sudo chgrp www-data /var/log/yiimp -R
    sudo chmod 775 /var/log/yiimp -R
    
    sudo chgrp www-data /var/stratum -R
    sudo chmod 775 /var/stratum

    sudo mkdir -p /var/yiimp/sauv
    sudo chgrp www-data /var/yiimp -R
    sudo chmod 775 /var/yiimp -R


    #Add to contrab screen-scrypt
    (crontab -l 2>/dev/null; echo "@reboot sleep 20 && /etc/screen-scrypt.sh") | crontab -

    #fix error screen main "service"
    sudo sed -i 's/service $webserver start/sudo service $webserver start/g' /var/web/yaamp/modules/thread/CronjobController.php
    sudo sed -i 's/service nginx stop/sudo service nginx stop/g' /var/web/yaamp/modules/thread/CronjobController.php

    #fix error screen main "backup sql frontend"
    sudo sed -i "s|/root/backup|/var/yiimp/sauv|g" /var/web/yaamp/core/backend/system.php
    sudo sed -i '14d' /var/web/yaamp/defaultconfig.php

    #Misc
    sudo mv $HOME/yiimp/ $HOME/yiimp-install-only-do-not-run-commands-from-this-folder
    sudo rm -rf /var/log/nginx/*
    
    #Hold update OpenSSL
    #If you want remove the hold : sudo apt-mark unhold openssl
    sudo apt-mark hold openssl

    #Restart service
    sudo systemctl restart cron.service
    sudo systemctl restart mysql
    sudo systemctl status mysql | sed -n "1,3p"
    sudo systemctl restart nginx.service
    sudo systemctl status nginx | sed -n "1,3p"
    sudo systemctl restart php7.3-fpm.service
    sudo systemctl status php7.3-fpm | sed -n "1,3p"


if [[ ("$rem_coins" == "y" || "$rem_coins" == "Y" || "$rem_coins" == "") ]]; then
   
    # Removing default coins (except Bitcoin - must leave one)
    echo
    echo -e "Removing default coins (except Bitcoin - must leave one)"
    echo
    sleep 3
    # will have to remove the $$$ ones from mysql manually
    sudo yiimp coin UNF delete
    sudo yiimp coin DES delete
    sudo yiimp coin KUMA delete
    sudo yiimp coin MEME delete
    sudo yiimp coin FOOT delete
    sudo yiimp coin UMO delete
    sudo yiimp coin G3N delete
    sudo yiimp coin SHND delete
    sudo yiimp coin WHIPPED delete
    sudo yiimp coin FLY delete
    sudo yiimp coin BUMBA delete
    sudo yiimp coin EBG delete
    sudo yiimp coin I0C delete
    sudo yiimp coin CAPT delete
    sudo yiimp coin PAK delete
    sudo yiimp coin EUC delete
    sudo yiimp coin GRE-OLD delete
    sudo yiimp coin PR delete
    sudo yiimp coin VGC delete
    sudo yiimp coin CFC delete
    sudo yiimp coin GAME delete
    sudo yiimp coin FONZ delete
    sudo yiimp coin DBIC delete
    sudo yiimp coin TRUMP delete
    sudo yiimp coin JIF delete
    sudo yiimp coin EVIL delete
    sudo yiimp coin EVO delete
    sudo yiimp coin LTC delete
    sudo yiimp coin LTCR delete
    sudo yiimp coin SANDG delete
    sudo yiimp coin RICHX delete
    sudo yiimp coin ADZ delete
    sudo yiimp coin DGCS delete
    sudo yiimp coin BOLI delete
    sudo yiimp coin LGBTQ delete
    sudo yiimp coin ZOOM delete
    sudo yiimp coin YOC delete
    sudo yiimp coin SIB delete
    sudo yiimp coin OPES delete
    sudo yiimp coin NKC delete
    sudo yiimp coin MMXVI delete
    sudo yiimp coin MBL delete
    sudo yiimp coin KNC delete
    sudo yiimp coin AR2 delete
    sudo yiimp coin AND delete
    sudo yiimp coin TROLL delete
    sudo yiimp coin DNET delete
    sudo yiimp coin DCR delete
    sudo yiimp coin EGC delete
    sudo yiimp coin MND delete
    sudo yiimp coin BNT delete
    sudo yiimp coin AMS delete
    sudo yiimp coin INFX delete
    sudo yiimp coin BSD delete
    sudo yiimp coin HTC delete
    sudo yiimp coin CZECO delete
    sudo yiimp coin EDRC delete
    sudo yiimp coin FTP delete
    sudo yiimp coin OP delete
    sudo yiimp coin CHAI delete
    sudo yiimp coin REV delete
    sudo yiimp coin PULSE delete
    sudo yiimp coin XCT delete
    sudo yiimp coin STS delete
    sudo yiimp coin EC delete
    sudo yiimp coin CYG delete
    sudo yiimp coin VAL delete
    sudo yiimp coin TBC delete
    sudo yiimp coin CRBIT delete
    sudo yiimp coin GMX delete
    sudo yiimp coin HODL delete
    sudo yiimp coin KLC delete
    sudo yiimp coin BUZZ delete
    sudo yiimp coin ADCN delete
    sudo yiimp coin RBIES delete
    sudo yiimp coin SEC delete
    sudo yiimp coin XID delete
    sudo yiimp coin BTCU delete
    sudo yiimp coin WARP delete
    sudo yiimp coin CPNC delete
    sudo yiimp coin HIRE delete
    sudo yiimp coin SLS delete
    sudo yiimp coin XHI delete
    sudo yiimp coin RADS delete
    sudo yiimp coin BTP delete
    sudo yiimp coin X2 delete
    sudo yiimp coin HMP delete
    sudo yiimp coin BRONZ delete
    sudo yiimp coin RUBIT delete
    sudo yiimp coin REP delete
    sudo yiimp coin SPL delete
    sudo yiimp coin CIONZ delete
    sudo yiimp coin SCRT delete
    sudo yiimp coin DEUR delete
    sudo yiimp coin VOX delete
    sudo yiimp coin CLUB delete
    sudo yiimp coin SCOT delete
    sudo yiimp coin FLOZ delete
    sudo yiimp coin STATS delete
    sudo yiimp coin HZDOGE delete
    sudo yiimp coin WLC delete
    sudo yiimp coin BST delete
    sudo yiimp coin BITUSD delete
    sudo yiimp coin BITCNY delete
    sudo yiimp coin FNX delete
    sudo yiimp coin APC delete
    sudo yiimp coin XLM delete
    sudo yiimp coin AGRS delete
    sudo yiimp coin DROP delete
    sudo yiimp coin AMP delete
    sudo yiimp coin ANTI delete
    sudo yiimp coin 1337 delete
    sudo yiimp coin TRBO delete
    sudo yiimp coin BIC delete
    sudo yiimp coin SOIL delete
    sudo yiimp coin OMNI delete
    sudo yiimp coin CUBE delete
    sudo yiimp coin BAC delete
    sudo yiimp coin WOP delete
    sudo yiimp coin FCT delete
    sudo yiimp coin PRT delete
    sudo yiimp coin CBIT delete
    sudo yiimp coin NEU delete
    sudo yiimp coin STEPS delete
    sudo yiimp coin EXP delete
    sudo yiimp coin BCY delete
    sudo yiimp coin PRIME delete
    sudo yiimp coin SHF delete
    sudo yiimp coin SWING delete
    sudo yiimp coin MI delete
    sudo yiimp coin MACRO delete
    sudo yiimp coin SC delete
    sudo yiimp coin GCR delete
    sudo yiimp coin MAPC delete
    sudo yiimp coin GCC delete
    sudo yiimp coin TX delete
    sudo yiimp coin ETH delete
    sudo yiimp coin CRE delete
    sudo yiimp coin AEON delete
    sudo yiimp coin GSY delete
    sudo yiimp coin CHIP delete
    sudo yiimp coin BTCHC delete
    sudo yiimp coin AXIOM delete
    sudo yiimp coin FUEL delete
    sudo yiimp coin BIOS delete
    sudo yiimp coin CPC delete
    sudo yiimp coin HNC delete
    sudo yiimp coin IBITS delete
    sudo yiimp coin DIGS delete
    sudo yiimp coin NOC delete
    sudo yiimp coin MCZ delete
    sudo yiimp coin BANX delete
    sudo yiimp coin CPN delete
    sudo yiimp coin SPRTS delete
    sudo yiimp coin SPROUT delete
    sudo yiimp coin NUKE delete
    sudo yiimp coin 2BACCO delete
    sudo yiimp coin FIC delete
    sudo yiimp coin LFO delete
    sudo yiimp coin VERSA delete
    sudo yiimp coin MCAR delete
    sudo yiimp coin CARB delete
    sudo yiimp coin ZUR delete
    sudo yiimp coin VAPE delete
    sudo yiimp coin TALK delete
    sudo yiimp coin RUM delete
    sudo yiimp coin PPCD delete
    sudo yiimp coin PHO delete
    sudo yiimp coin P0001 delete
    sudo yiimp coin NODE delete
    sudo yiimp coin MRC delete
    sudo yiimp coin ISO delete
    sudo yiimp coin HANSA delete
    sudo yiimp coin FX01 delete
    sudo yiimp coin FRSH delete
    sudo yiimp coin FIMK delete
    sudo yiimp coin FAIL delete
    sudo yiimp coin DRM delete
    sudo yiimp coin DRK delete
    sudo yiimp coin CV2 delete
    sudo yiimp coin BTRHA delete
    sudo yiimp coin ALCUREX delete
    sudo yiimp coin BNX delete
    sudo yiimp coin QUIT delete
    sudo yiimp coin V delete
    sudo yiimp coin PLC delete
    sudo yiimp coin GRW delete
    sudo yiimp coin DUO delete
    sudo yiimp coin ANI delete
    sudo yiimp coin CDC delete
    sudo yiimp coin CX delete
    sudo yiimp coin MARS delete
    sudo yiimp coin SHA delete
    sudo yiimp coin FETISH delete
    sudo yiimp coin EXC delete
    sudo yiimp coin BDSM delete
    sudo yiimp coin OFF delete
    sudo yiimp coin EMC delete
    sudo yiimp coin BLZ delete
    sudo yiimp coin CHAO delete
    sudo yiimp coin CNO delete
    sudo yiimp coin FUNK delete
    sudo yiimp coin UNIC delete
    sudo yiimp coin DUCK delete
    sudo yiimp coin BSY delete
    sudo yiimp coin SPN delete
    sudo yiimp coin IPC delete
    sudo yiimp coin $MINEZ delete
    sudo yiimp coin $MINEW delete
    sudo yiimp coin ADD delete
    sudo yiimp coin $MINE delete
    sudo yiimp coin FTCC delete
    sudo yiimp coin GXG delete
    sudo yiimp coin CIV delete
    sudo yiimp coin TOP delete
    sudo yiimp coin TTY delete
    sudo yiimp coin NTC delete
    sudo yiimp coin KIWI delete
    sudo yiimp coin XPL delete
    sudo yiimp coin XGR delete
    sudo yiimp coin $$$ delete
    sudo yiimp coin 66 delete
    sudo yiimp coin MDC delete
    sudo yiimp coin SVC delete
    sudo yiimp coin DARK delete
    sudo yiimp coin POP delete
    sudo yiimp coin WSX delete
    sudo yiimp coin DOT delete
    sudo yiimp coin YOVI delete
    sudo yiimp coin HXX delete
    sudo yiimp coin CRPS delete
    sudo yiimp coin BAM delete
    sudo yiimp coin SJW delete
    sudo yiimp coin GMCX delete
    sudo yiimp coin SPX delete
    sudo yiimp coin EXT delete
    sudo yiimp coin TENNET delete
    sudo yiimp coin KC delete
    sudo yiimp coin BLUS delete
    sudo yiimp coin XRA delete
    sudo yiimp coin SPEC delete
    sudo yiimp coin EA delete
    sudo yiimp coin TAGR delete
    sudo yiimp coin HAZE delete
    sudo yiimp coin TAM delete
    sudo yiimp coin POLY delete
    sudo yiimp coin INDEX delete
    sudo yiimp coin GENI delete
    sudo yiimp coin BUCKS delete
    sudo yiimp coin SPKTR delete
    sudo yiimp coin GENE delete
    sudo yiimp coin GRM delete
    sudo yiimp coin DIBS delete
    sudo yiimp coin GTFO delete
    sudo yiimp coin FUTC delete
    sudo yiimp coin XVI delete
    sudo yiimp coin GLOBE delete
    sudo yiimp coin SMSR delete
    sudo yiimp coin CIRC delete
    sudo yiimp coin WOC2 delete
    sudo yiimp coin NODX delete
    sudo yiimp coin ERC delete
    sudo yiimp coin SEN delete
    sudo yiimp coin SAK delete
    sudo yiimp coin EOC delete
    sudo yiimp coin TRANSF delete
    sudo yiimp coin GEN delete
    sudo yiimp coin DRKT delete
    sudo yiimp coin XCE delete
    sudo yiimp coin XPH delete
    sudo yiimp coin FIST delete
    sudo yiimp coin DUB delete
    sudo yiimp coin VAPOR delete
    sudo yiimp coin ARPA delete
    sudo yiimp coin BNB delete
    sudo yiimp coin NANAS delete
    sudo yiimp coin SEEDS delete
    sudo yiimp coin OPTION delete
    sudo yiimp coin DRA delete
    sudo yiimp coin GLUCK delete
    sudo yiimp coin EXB delete
    sudo yiimp coin GREED delete
    sudo yiimp coin MOIN delete
    sudo yiimp coin VCOIN delete
    sudo yiimp coin TWLV delete
    sudo yiimp coin RDN delete
    sudo yiimp coin PSY delete
    sudo yiimp coin ECC delete
    sudo yiimp coin SNRG delete
    sudo yiimp coin ADC delete
    sudo yiimp coin CREVA delete
    sudo yiimp coin VCN delete
    sudo yiimp coin 32BIT delete
    sudo yiimp coin XNA delete
    sudo yiimp coin TWERK delete
    sudo yiimp coin CS delete
    sudo yiimp coin GENIUS delete
    sudo yiimp coin PRE delete
    sudo yiimp coin NICE delete
    sudo yiimp coin CORG delete
    sudo yiimp coin DB delete
    sudo yiimp coin EQM delete
    sudo yiimp coin FADE delete
    sudo yiimp coin SED delete
    sudo yiimp coin SKB delete
    sudo yiimp coin TNG delete
    sudo yiimp coin ARB delete
    sudo yiimp coin DCC delete
    sudo yiimp coin PTA delete
    sudo yiimp coin MRB delete
    sudo yiimp coin BTA delete
    sudo yiimp coin GRT delete
    sudo yiimp coin AST delete
    sudo yiimp coin BA delete
    sudo yiimp coin KRAK delete
    sudo yiimp coin M1 delete
    sudo yiimp coin 16BIT delete
    sudo yiimp coin TB delete
    sudo yiimp coin BIT16 delete
    sudo yiimp coin CLV delete
    sudo yiimp coin SHELL delete
    sudo yiimp coin LIMX delete
    sudo yiimp coin BTI delete
    sudo yiimp coin FSN delete
    sudo yiimp coin TKT delete
    sudo yiimp coin FCS delete
    sudo yiimp coin VTN delete
    sudo yiimp coin EPC delete
    sudo yiimp coin PKB delete
    sudo yiimp coin GAM delete
    sudo yiimp coin ISL delete
    sudo yiimp coin VIRAL delete
    sudo yiimp coin UTLE delete
    sudo yiimp coin PNC delete
    sudo yiimp coin GOAT delete
    sudo yiimp coin EPY delete
    sudo yiimp coin CTO delete
    sudo yiimp coin SPC delete
    sudo yiimp coin GRAV delete
    sudo yiimp coin GPH delete
    sudo yiimp coin UNIT delete
    sudo yiimp coin BUB delete
    sudo yiimp coin BTX delete
    sudo yiimp coin TDFB delete
    sudo yiimp coin SPHR delete
    sudo yiimp coin GUM delete
    sudo yiimp coin XMS delete
    sudo yiimp coin XSEED delete
    sudo yiimp coin XNX delete
    sudo yiimp coin XTP delete
    sudo yiimp coin DOX delete
    sudo yiimp coin QTZ delete
    sudo yiimp coin UNAT-skein delete
    sudo yiimp coin AIB delete
    sudo yiimp coin GRAM delete
    sudo yiimp coin SIGU delete
    sudo yiimp coin BLITZ delete
    sudo yiimp coin NIRO delete
    sudo yiimp coin HUGE delete
    sudo yiimp coin 7 delete
    sudo yiimp coin DRZ delete
    sudo yiimp coin LUX delete
    sudo yiimp coin UIS-qubit delete
    sudo yiimp coin UIS-skein delete
    sudo yiimp coin SLING delete
    sudo yiimp coin COV delete
    sudo yiimp coin NTRN delete
    sudo yiimp coin CTK delete
    sudo yiimp coin CF delete
    sudo yiimp coin CGN delete
    sudo yiimp coin ACP delete
    sudo yiimp coin OK delete
    sudo yiimp coin 8BIT delete
    sudo yiimp coin IEC delete
    sudo yiimp coin P7C delete
    sudo yiimp coin HZT delete
    sudo yiimp coin LEA delete
    sudo yiimp coin GIZ delete
    sudo yiimp coin ETRUST delete
    sudo yiimp coin XPRO delete
    sudo yiimp coin TRON delete
    sudo yiimp coin DECR delete
    sudo yiimp coin RICE delete
    sudo yiimp coin STP delete
    sudo yiimp coin NXE delete
    sudo yiimp coin AECC delete
    sudo yiimp coin PLANET delete
    sudo yiimp coin FIRE delete
    sudo yiimp coin ANAL delete
    sudo yiimp coin MTLMC3 delete
    sudo yiimp coin TWIST delete
    sudo yiimp coin CRIME delete
    sudo yiimp coin BTCR delete
    sudo yiimp coin TEC delete
    sudo yiimp coin KARMA delete
    sudo yiimp coin TCX delete
    sudo yiimp coin TAB delete
    sudo yiimp coin NDOGE delete
    sudo yiimp coin GIFT delete
    sudo yiimp coin BBCC delete
    sudo yiimp coin TRICK delete
    sudo yiimp coin DGMS delete
    sudo yiimp coin CCB delete
    sudo yiimp coin OZC delete
    sudo yiimp coin STK delete
    sudo yiimp coin SIC delete
    sudo yiimp coin EGG delete
    sudo yiimp coin EKN delete
    sudo yiimp coin MRP delete
    sudo yiimp coin QORA delete
    sudo yiimp coin PXL delete
    sudo yiimp coin CRY delete
    sudo yiimp coin URC delete
    sudo yiimp coin ICN delete
    sudo yiimp coin OCTO delete
    sudo yiimp coin EUR delete
    sudo yiimp coin CAD delete
    sudo yiimp coin CC delete
    sudo yiimp coin XEM delete
    sudo yiimp coin SLFI delete
    sudo yiimp coin 256 delete
    sudo yiimp coin ICASH delete
    sudo yiimp coin BTCRY delete
    sudo yiimp coin XDB delete
    sudo yiimp coin ZIRK delete
    sudo yiimp coin CRAVE delete
    sudo yiimp coin BITZ delete
    sudo yiimp coin OMC delete
    sudo yiimp coin PAY delete
    sudo yiimp coin LDOGE delete
    sudo yiimp coin RBT delete
    sudo yiimp coin ASN delete
    sudo yiimp coin MINE delete
    sudo yiimp coin XAU delete
    sudo yiimp coin XFC delete
    sudo yiimp coin UNC delete
    sudo yiimp coin XCO delete
    sudo yiimp coin VOYA delete
    sudo yiimp coin XVC delete
    sudo yiimp coin WBB delete
    sudo yiimp coin ECASH delete
    sudo yiimp coin MTR delete
    sudo yiimp coin NSR delete
    sudo yiimp coin GSM delete
    sudo yiimp coin PTY delete
    sudo yiimp coin LYB delete
    sudo yiimp coin SUP delete
    sudo yiimp coin CIN delete
    sudo yiimp coin DD delete
    sudo yiimp coin SMAC delete
    sudo yiimp coin GRID delete
    sudo yiimp coin SLM delete
    sudo yiimp coin LTS delete
    sudo yiimp coin XTC delete
    sudo yiimp coin DGORE delete
    sudo yiimp coin BITB delete
    sudo yiimp coin BEAN delete
    sudo yiimp coin PEN delete
    sudo yiimp coin NVCD delete
    sudo yiimp coin XPD delete
    sudo yiimp coin CBX delete
    sudo yiimp coin CELL delete
    sudo yiimp coin KOBO delete
    sudo yiimp coin LQD delete
    sudo yiimp coin XTR delete
    sudo yiimp coin 10K delete
    sudo yiimp coin MYST delete
    sudo yiimp coin BTCS delete
    sudo yiimp coin XPB delete
    sudo yiimp coin CETI delete
    sudo yiimp coin OMA delete
    sudo yiimp coin CCC delete
    sudo yiimp coin XFB delete
    sudo yiimp coin OBS delete
    sudo yiimp coin SOON delete
    sudo yiimp coin GIG delete
    sudo yiimp coin XAP delete
    sudo yiimp coin XBC delete
    sudo yiimp coin XCH delete
    sudo yiimp coin XCN delete
    sudo yiimp coin XCP delete
    sudo yiimp coin XDP delete
    sudo yiimp coin XUSD delete
    sudo yiimp coin YACC delete
    sudo yiimp coin 1CR delete
    sudo yiimp coin ACH delete
    sudo yiimp coin ADN delete
    sudo yiimp coin BCN delete
    sudo yiimp coin BELA delete
    sudo yiimp coin C2 delete
    sudo yiimp coin CGA delete
    sudo yiimp coin CHA delete
    sudo yiimp coin CNMT delete
    sudo yiimp coin CYC delete
    sudo yiimp coin DIEM delete
    sudo yiimp coin DSH delete
    sudo yiimp coin FLDC delete
    sudo yiimp coin GAP delete
    sudo yiimp coin GDN delete
    sudo yiimp coin GEMZ delete
    sudo yiimp coin GOLD delete
    sudo yiimp coin GRS delete
    sudo yiimp coin HIRO delete
    sudo yiimp coin HZ delete
    sudo yiimp coin JLH delete
    sudo yiimp coin LTBC delete
    sudo yiimp coin MAID delete
    sudo yiimp coin MCN delete
    sudo yiimp coin MIL delete
    sudo yiimp coin MMC delete
    sudo yiimp coin MMNXT delete
    sudo yiimp coin MNTA delete
    sudo yiimp coin MRS delete
    sudo yiimp coin NBT delete
    sudo yiimp coin NOXT delete
    sudo yiimp coin NXTI delete
    sudo yiimp coin PIGGY delete
    sudo yiimp coin PRC delete
    sudo yiimp coin RIC delete
    sudo yiimp coin SJCX delete
    sudo yiimp coin SQL delete
    sudo yiimp coin SRCC delete
    sudo yiimp coin SWARM delete
    sudo yiimp coin UNITY delete
    sudo yiimp coin WOLF delete
    sudo yiimp coin XWC delete
    sudo yiimp coin FSC2 delete
    sudo yiimp coin RBR delete
    sudo yiimp coin CSD delete
    sudo yiimp coin XDE delete
    sudo yiimp coin XPC delete
    sudo yiimp coin DGD delete
    sudo yiimp coin ARI delete
    sudo yiimp coin XBS delete
    sudo yiimp coin USDT delete
    sudo yiimp coin GP delete
    sudo yiimp coin CON delete
    sudo yiimp coin EAGS delete
    sudo yiimp coin NKA delete
    sudo yiimp coin INCA delete
    sudo yiimp coin XSP delete
    sudo yiimp coin BCR delete
    sudo yiimp coin BLK delete
    sudo yiimp coin SBIT delete
    sudo yiimp coin UIS delete
    sudo yiimp coin HGC delete
    sudo yiimp coin 2015 delete
    sudo yiimp coin GMC delete
    sudo yiimp coin VMC delete
    sudo yiimp coin ggggg delete
    sudo yiimp coin UCI delete
    sudo yiimp coin EQX delete
    sudo yiimp coin STR delete
    sudo yiimp coin TAK delete
    sudo yiimp coin TEK delete
    sudo yiimp coin TES delete
    sudo yiimp coin TGC delete
    sudo yiimp coin TOR delete
    sudo yiimp coin TRC delete
    sudo yiimp coin UNB delete
    sudo yiimp coin USDe delete
    sudo yiimp coin XCR delete
    sudo yiimp coin XJO delete
    sudo yiimp coin XLB delete
    sudo yiimp coin YAC delete
    sudo yiimp coin YBC delete
    sudo yiimp coin ZCC delete
    sudo yiimp coin ZED delete
    sudo yiimp coin ADT delete
    sudo yiimp coin ASC delete
    sudo yiimp coin BAT delete
    sudo yiimp coin COL delete
    sudo yiimp coin CPR delete
    sudo yiimp coin CTM delete
    sudo yiimp coin DBL delete
    sudo yiimp coin DMC delete
    sudo yiimp coin ELP delete
    sudo yiimp coin FLAP delete
    sudo yiimp coin GME delete
    sudo yiimp coin LEAF delete
    sudo yiimp coin LOT delete
    sudo yiimp coin MEM delete
    sudo yiimp coin MEOW delete
    sudo yiimp coin MST delete
    sudo yiimp coin RBBT delete
    sudo yiimp coin RED delete
    sudo yiimp coin TIPS delete
    sudo yiimp coin TIX delete
    sudo yiimp coin XNC delete
    sudo yiimp coin ZEIT delete
    sudo yiimp coin AC delete
    sudo yiimp coin ACOIN delete
    sudo yiimp coin AGS delete
    sudo yiimp coin ALF delete
    sudo yiimp coin ALN delete
    sudo yiimp coin AMC delete
    sudo yiimp coin ARG delete
    sudo yiimp coin AUR delete
    sudo yiimp coin BCX delete
    sudo yiimp coin BEN delete
    sudo yiimp coin BET delete
    sudo yiimp coin BNCR delete
    sudo yiimp coin BOST delete
    sudo yiimp coin BQC delete
    sudo yiimp coin BTB delete
    sudo yiimp coin BTE delete
    sudo yiimp coin BTG delete
    sudo yiimp coin BUK delete
    sudo yiimp coin CACH delete
    sudo yiimp coin CAP delete
    sudo yiimp coin CASH delete
    sudo yiimp coin CGB delete
    sudo yiimp coin CINNI delete
    sudo yiimp coin CMC delete
    sudo yiimp coin CNC delete
    sudo yiimp coin CNL delete
    sudo yiimp coin COMM delete
    sudo yiimp coin COOL delete
    sudo yiimp coin CRACK delete
    sudo yiimp coin CRC delete
    sudo yiimp coin CSC delete
    sudo yiimp coin DEM delete
    sudo yiimp coin DMD delete
    sudo yiimp coin DRKC delete
    sudo yiimp coin DT delete
    sudo yiimp coin DVC delete
    sudo yiimp coin EAC delete
    sudo yiimp coin ELC delete
    sudo yiimp coin EMD delete
    sudo yiimp coin EZC delete
    sudo yiimp coin FFC delete
    sudo yiimp coin FLT delete
    sudo yiimp coin FRAC delete
    sudo yiimp coin FRK delete
    sudo yiimp coin FST delete
    sudo yiimp coin GDC delete
    sudo yiimp coin GLC delete
    sudo yiimp coin GLD delete
    sudo yiimp coin GLX delete
    sudo yiimp coin GLYPH delete
    sudo yiimp coin GUE delete
    sudo yiimp coin HBN delete
    sudo yiimp coin HVC delete
    sudo yiimp coin ICB delete
    sudo yiimp coin IXC delete
    sudo yiimp coin JKC delete
    sudo yiimp coin KDC delete
    sudo yiimp coin KGC delete
    sudo yiimp coin LAB delete
    sudo yiimp coin LGD delete
    sudo yiimp coin LK7 delete
    sudo yiimp coin LKY delete
    sudo yiimp coin LTB delete
    sudo yiimp coin LTCX delete
    sudo yiimp coin LYC delete
    sudo yiimp coin MED delete
    sudo yiimp coin MNC delete
    sudo yiimp coin MZC delete
    sudo yiimp coin NAN delete
    sudo yiimp coin NBL delete
    sudo yiimp coin NEC delete
    sudo yiimp coin NRB delete
    sudo yiimp coin NRS delete
    sudo yiimp coin NYAN delete
    sudo yiimp coin OSC delete
    sudo yiimp coin PHS delete
    sudo yiimp coin Points delete
    sudo yiimp coin PSEUD delete
    sudo yiimp coin PTS delete
    sudo yiimp coin PYC delete
    sudo yiimp coin RT2 delete
    sudo yiimp coin RYC delete
    sudo yiimp coin SAT2 delete
    sudo yiimp coin SBC delete
    sudo yiimp coin SHLD delete
    sudo yiimp coin SILK delete
    sudo yiimp coin SMC delete
    sudo yiimp coin SOLE delete
    sudo yiimp coin SPA delete
    sudo yiimp coin SPT delete
    sudo yiimp coin SSV delete
    sudo yiimp coin EMC2 delete
    sudo yiimp coin GIMP delete
    sudo yiimp coin GRC delete
    sudo yiimp coin KRYP delete
    sudo yiimp coin MIC delete
    sudo yiimp coin MOTO delete
    sudo yiimp coin MSC delete
    sudo yiimp coin NIC delete
    sudo yiimp coin NWO delete
    sudo yiimp coin PLCN delete
    sudo yiimp coin PROZ delete
    sudo yiimp coin SONG delete
    sudo yiimp coin SPUDS delete
    sudo yiimp coin SQC delete
    sudo yiimp coin VOXP delete
    sudo yiimp coin VTX delete
    sudo yiimp coin XRC delete
    sudo yiimp coin XSX delete
    sudo yiimp coin XVG delete
    sudo yiimp coin DON delete
    sudo yiimp coin FJC delete
    sudo yiimp coin GCN delete
    sudo yiimp coin GRN delete
    sudo yiimp coin GUA delete
    sudo yiimp coin HAM delete
    sudo yiimp coin HEX delete
    sudo yiimp coin IFC delete
    sudo yiimp coin IRL delete
    sudo yiimp coin KARM delete
    sudo yiimp coin MINT delete
    sudo yiimp coin MOON delete
    sudo yiimp coin MTLMC delete
    sudo yiimp coin NMC delete
    sudo yiimp coin NYC delete
    sudo yiimp coin ORB delete
    sudo yiimp coin PAC delete
    sudo yiimp coin PCC delete
    sudo yiimp coin PHC delete
    sudo yiimp coin PPC delete
    sudo yiimp coin RC delete
    sudo yiimp coin SXC delete
    sudo yiimp coin TRL delete
    sudo yiimp coin USD delete
    sudo yiimp coin VTA delete
    sudo yiimp coin XPM delete
    sudo yiimp coin BURST delete
    sudo yiimp coin LTCD delete
    sudo yiimp coin CRAIG delete
    sudo yiimp coin TIT delete
    sudo yiimp coin BSTY delete
    sudo yiimp coin GNS delete
    sudo yiimp coin DCN delete
    sudo yiimp coin PXI delete
    sudo yiimp coin MLS delete
    sudo yiimp coin ROS delete
    sudo yiimp coin STV delete
    sudo yiimp coin OPAL delete
    sudo yiimp coin EXCL delete
    sudo yiimp coin PYRA delete
    sudo yiimp coin NET delete
    sudo yiimp coin SEED delete
    sudo yiimp coin PND delete
    sudo yiimp coin GHC delete
    sudo yiimp coin DOPE delete
    sudo yiimp coin ONE delete
    sudo yiimp coin BLEU delete
    sudo yiimp coin BVC delete
    sudo yiimp coin CAGE delete
    sudo yiimp coin CDN delete
    sudo yiimp coin CESC delete
    sudo yiimp coin CLR delete
    sudo yiimp coin CZC delete
    sudo yiimp coin CHILD delete
    sudo yiimp coin XQN delete
    sudo yiimp coin RDD delete
    sudo yiimp coin NXT delete
    sudo yiimp coin BC delete
    sudo yiimp coin MYR-qubit delete
    sudo yiimp coin UTC delete
    sudo yiimp coin 888 delete
    sudo yiimp coin EFL delete
    sudo yiimp coin DIME delete
    sudo yiimp coin SLR delete
    sudo yiimp coin WATER delete
    sudo yiimp coin NLG delete
    sudo yiimp coin GIVE delete
    sudo yiimp coin WC delete
    sudo yiimp coin NOBL delete
    sudo yiimp coin BITS delete
    sudo yiimp coin BLU delete
    sudo yiimp coin OC delete
    sudo yiimp coin THC delete
    sudo yiimp coin ENRG delete
    sudo yiimp coin SHIBE delete
    sudo yiimp coin SFR delete
    sudo yiimp coin NAUT delete
    sudo yiimp coin VRC delete
    sudo yiimp coin CURE delete
    sudo yiimp coin SYNC delete
    sudo yiimp coin BLC delete
    sudo yiimp coin XSI delete
    sudo yiimp coin XC delete
    sudo yiimp coin XDQ delete
    sudo yiimp coin MMXIV delete
    sudo yiimp coin CAIX delete
    sudo yiimp coin BBR delete
    sudo yiimp coin HYPER delete
    sudo yiimp coin CCN delete
    sudo yiimp coin KTK delete
    sudo yiimp coin MUGA delete
    sudo yiimp coin VOOT delete
    sudo yiimp coin BN delete
    sudo yiimp coin XMR delete
    sudo yiimp coin CLOAK delete
    sudo yiimp coin CHCC delete
    sudo yiimp coin BURN delete
    sudo yiimp coin KORE delete
    sudo yiimp coin RZR delete
    sudo yiimp coin XDN delete
    sudo yiimp coin MIN delete
    sudo yiimp coin TECH delete
    sudo yiimp coin GML delete
    sudo yiimp coin TRK delete
    sudo yiimp coin WKC delete
    sudo yiimp coin QTL delete
    sudo yiimp coin XXX delete
    sudo yiimp coin AERO delete
    sudo yiimp coin TRUST delete
    sudo yiimp coin BRIT delete
    sudo yiimp coin JUDGE delete
    sudo yiimp coin NAV delete
    sudo yiimp coin XST delete
    sudo yiimp coin APEX delete
    sudo yiimp coin ZET delete
    sudo yiimp coin BTCD delete
    sudo yiimp coin KEY delete
    sudo yiimp coin NUD delete
    sudo yiimp coin TRI delete
    sudo yiimp coin PES delete
    sudo yiimp coin ICG delete
    sudo yiimp coin UNO delete
    sudo yiimp coin ESC delete
    sudo yiimp coin PINK delete
    sudo yiimp coin IOC delete
    sudo yiimp coin SDC delete
    sudo yiimp coin RAW delete
    sudo yiimp coin MAX delete
    sudo yiimp coin LXC delete
    sudo yiimp coin BOOM delete
    sudo yiimp coin BOB delete
    sudo yiimp coin UNAT delete
    sudo yiimp coin MWC delete
    sudo yiimp coin VAULT delete
    sudo yiimp coin FC2 delete
    sudo yiimp coin SSD delete
    sudo yiimp coin BIG delete
    sudo yiimp coin GB delete
    sudo yiimp coin ROOT delete
    sudo yiimp coin AXR delete
    sudo yiimp coin RIPO delete
    sudo yiimp coin FIBRE delete
    sudo yiimp coin SHADE delete
    sudo yiimp coin FLEX delete
    sudo yiimp coin XBOT delete
    sudo yiimp coin XCASH delete
    sudo yiimp coin FLO delete
    sudo yiimp coin NKT delete
    sudo yiimp coin TTC delete
    sudo yiimp coin CLAM delete
    sudo yiimp coin VTR delete
    sudo yiimp coin SUPER delete
    sudo yiimp coin NOO delete
    sudo yiimp coin XPY delete
    sudo yiimp coin SMLY delete
    sudo yiimp coin BCENT delete
    sudo yiimp coin DS delete
    sudo yiimp coin FAIR delete
    sudo yiimp coin EVENT delete
    sudo yiimp coin HUC delete
    sudo yiimp coin CAT delete
    sudo yiimp coin WDC delete
    sudo yiimp coin BTM delete
    sudo yiimp coin RMS delete
    sudo yiimp coin ANC delete
    sudo yiimp coin MEC delete
    sudo yiimp coin MONA delete
    sudo yiimp coin DGC delete
    sudo yiimp coin BCF delete
    sudo yiimp coin SYS delete
    sudo yiimp coin ULTC delete
    sudo yiimp coin CXC delete
    sudo yiimp coin METAL delete
    sudo yiimp coin PTC delete
    sudo yiimp coin SPR delete
    sudo yiimp coin CBR delete
    sudo yiimp coin FIND delete
    sudo yiimp coin AM delete
    sudo yiimp coin FUD delete
    sudo yiimp coin ERM delete
    sudo yiimp coin VIA delete
    sudo yiimp coin CKC delete
    sudo yiimp coin BTS delete
    sudo yiimp coin DEAF delete
    sudo yiimp coin HIC delete
    sudo yiimp coin BAY delete
    sudo yiimp coin VIOR delete
    sudo yiimp coin VPN delete
    sudo yiimp coin MN delete
    sudo yiimp coin EXE delete
    sudo yiimp coin PFC delete
    sudo yiimp coin GSX delete
    sudo yiimp coin BRXv2 delete
    sudo yiimp coin ACHK delete
    sudo yiimp coin CRYPT delete
    sudo yiimp coin HLC delete
    sudo yiimp coin SWIFT delete
    sudo yiimp coin ARCH delete    
    sudo yiimp coin GAIA delete
    sudo yiimp coin WWC delete
    sudo yiimp coin XRP delete
    sudo yiimp coin LMR delete
    sudo yiimp coin MNE delete
    sudo yiimp coin CRW delete
    sudo yiimp coin VDO delete
    sudo yiimp coin NOPE delete
    sudo yiimp coin XWT delete
    sudo yiimp coin DTC delete
    sudo yiimp coin SMBR delete
    sudo yiimp coin HYP delete
    sudo yiimp coin QBK delete
    sudo yiimp coin CENT delete
    sudo yiimp coin BLOCK delete
    sudo yiimp coin CATC delete
    sudo yiimp coin SCSY delete
    sudo yiimp coin GUN delete
    sudo yiimp coin ABY delete
    sudo yiimp coin BALLS delete
    sudo yiimp coin QSLV delete
    sudo yiimp coin U delete
    sudo yiimp coin BYC delete
    sudo yiimp coin BUN delete
    sudo yiimp coin ZER delete
    sudo yiimp coin ZNY delete
    sudo yiimp coin MRY delete
    sudo yiimp coin CANN delete
    sudo yiimp coin POT delete
    sudo yiimp coin TAG delete
    sudo yiimp coin DOGE delete
    sudo yiimp coin RBY delete
    sudo yiimp coin NOTE delete
    sudo yiimp coin NVC delete
    sudo yiimp coin 42 delete
    sudo yiimp coin JBS delete
    sudo yiimp coin LSD delete
    sudo yiimp coin J delete
    sudo yiimp coin SLG delete
    sudo yiimp coin VIK delete
    sudo yiimp coin RPC delete
    sudo yiimp coin XG delete
    sudo yiimp coin DP delete
    sudo yiimp coin MARYJ delete
    sudo yiimp coin XMG delete
    sudo yiimp coin RUBLE delete
    sudo yiimp coin XCLD delete
    sudo yiimp coin 007 delete
    sudo yiimp coin GO delete
    sudo yiimp coin BFT delete
    sudo yiimp coin RVN delete
    sudo yiimp coin RFR delete
    sudo yiimp coin LOOM delete
    sudo yiimp coin MFT delete
    sudo yiimp coin BKX delete
    sudo yiimp coin NLC2 delete
    sudo yiimp coin CMCT delete
    sudo yiimp coin TUBE delete
    sudo yiimp coin OCN delete
    sudo yiimp coin GTO delete
    sudo yiimp coin NGC delete
    sudo yiimp coin AID delete
    sudo yiimp coin STORM delete
    sudo yiimp coin BLT delete
    sudo yiimp coin PRO delete
    sudo yiimp coin DMT delete
    sudo yiimp coin UP delete
    sudo yiimp coin LRC delete
    sudo yiimp coin TUSD delete
    sudo yiimp coin TRX delete
    sudo yiimp coin BCPT delete
    sudo yiimp coin VEE delete
    sudo yiimp coin ZRX delete
    sudo yiimp coin WAXP delete
    sudo yiimp coin SRN delete
    sudo yiimp coin IGINS delete
    sudo yiimp coin UKG delete
    sudo yiimp coin ENG delete
    sudo yiimp coin POWR delete
    sudo yiimp coin MER delete
    sudo yiimp coin VIB delete
    sudo yiimp coin RCN delete
    sudo yiimp coin SALT delete
    sudo yiimp coin MANA delete
    sudo yiimp coin ADA delete
    sudo yiimp coin XMY delete
    sudo yiimp coin BSC delete
    sudo yiimp coin SKC delete
    sudo yiimp coin LOG delete
    sudo yiimp coin DRP delete
    sudo yiimp coin CHC delete
    sudo yiimp coin FLAX delete
    sudo yiimp coin HEDG delete
    sudo yiimp coin ILM delete
    sudo yiimp coin MYR delete
    sudo yiimp coin BOD delete
    sudo yiimp coin CYP delete
    sudo yiimp coin ZRC delete
    sudo yiimp coin DASH delete
    sudo yiimp coin AMBER delete
    sudo yiimp coin BTQ delete
    sudo yiimp coin HTML5 delete
    sudo yiimp coin HAL delete
    sudo yiimp coin NEOS delete
    sudo yiimp coin XAI delete
    sudo yiimp coin DGB delete
    sudo yiimp coin MDT delete
    sudo yiimp coin GEO delete
    sudo yiimp coin MUE delete
    sudo yiimp coin SRC delete
    sudo yiimp coin QRK delete
    sudo yiimp coin PXC delete
    sudo yiimp coin FTC delete
    sudo yiimp coin URO delete
    sudo yiimp coin UFO delete
    sudo yiimp coin VTC delete
    sudo yiimp coin XDC delete
    sudo yiimp coin START delete
    sudo yiimp coin IDC delete
    sudo yiimp coin NXS delete
    sudo yiimp coin RVR delete
    sudo yiimp coin PIVX delete
    sudo yiimp coin STEEM delete
    sudo yiimp coin LSK delete
    sudo yiimp coin LBC delete
    sudo yiimp coin STRAT delete
    sudo yiimp coin ETC delete
    sudo yiimp coin ARDR delete
    sudo yiimp coin XZC delete
    sudo yiimp coin NEO delete
    sudo yiimp coin ZEC delete
    sudo yiimp coin UBQ delete
    sudo yiimp coin KMD delete
    sudo yiimp coin ION delete
    sudo yiimp coin SWT delete
    sudo yiimp coin MLN delete
    sudo yiimp coin ARK delete
    sudo yiimp coin INCNT delete
    sudo yiimp coin GBYTE delete
    sudo yiimp coin GNT delete
    sudo yiimp coin EDG delete
    sudo yiimp coin MED delete
    sudo yiimp coin SPC delete
    sudo yiimp coin OST delete
    sudo yiimp coin MOC delete
    sudo yiimp coin ZIL delete
    sudo yiimp coin PAX delete
    sudo yiimp coin PAL delete
    sudo yiimp coin PMA delete
    sudo yiimp coin NPXS delete
    sudo yiimp coin XHV delete
    sudo yiimp coin IHT delete
    sudo yiimp coin BOXX delete
    sudo yiimp coin EDR delete
    sudo yiimp coin DTA delete
    sudo yiimp coin MET delete
    sudo yiimp coin ENJ delete
    sudo yiimp coin UPP delete
    sudo yiimp coin HYDRO delete
    sudo yiimp coin IGNIS delete
    sudo yiimp coin DNT delete
    sudo yiimp coin BCH delete
    sudo yiimp coin QTUM delete
    sudo yiimp coin PART delete
    sudo yiimp coin CVC delete
    sudo yiimp coin OMG delete
    sudo yiimp coin ADX delete
    sudo yiimp coin STORJ delete
    sudo yiimp coin MTL delete
    sudo yiimp coin FUN delete
    sudo yiimp coin MCO delete
    sudo yiimp coin XEL delete
    sudo yiimp coin DCT delete
    sudo yiimp coin SNT delete
    sudo yiimp coin NMR delete
    sudo yiimp coin PTOY delete
    sudo yiimp coin QRL delete
    sudo yiimp coin 1ST delete
    sudo yiimp coin ANT delete
    sudo yiimp coin HMQ delete
    sudo yiimp coin GUP delete
    sudo yiimp coin DENT delete
    sudo yiimp coin MOBI delete
    sudo yiimp coin LBA delete
    sudo yiimp coin JNT delete
    sudo yiimp coin USDS delete
    sudo yiimp coin SOLVE delete
    sudo yiimp coin NCASH delete
    sudo yiimp coin XNK delete
    sudo yiimp coin IOST delete
    sudo yiimp coin BSV delete
    sudo yiimp coin ZEN delete
    sudo yiimp coin GNO delete
    sudo yiimp coin RLC delete
    sudo yiimp coin WINGS delete
    sudo yiimp coin MORE delete
    sudo yiimp coin SBD delete
    sudo yiimp coin WAVES delete
    sudo yiimp coin IOTX delete
    sudo yiimp coin VITE delete
    sudo yiimp coin DRGN delete
    sudo yiimp coin BTM delete
    sudo yiimp coin QNT delete
    sudo yiimp coin ELF delete
    sudo yiimp coin BTU delete
    sudo yiimp coin DRGN delete
    sudo yiimp coin BTT delete
    sudo yiimp coin SPND delete
    sudo yiimp coin $$$ delete

    echo
    echo -e "Default coin removal completed!"
    echo
fi

    echo
    echo -e "$GREEN Done...$COL_RESET"
    sleep 3

    echo
    echo
    echo
    echo -e "$GREEN***************************$COL_RESET"
    echo -e "$GREEN Yiimp Install Script v0.2 $COL_RESET"
    echo -e "$GREEN Finish !!! $COL_RESET"
    echo -e "$GREEN***************************$COL_RESET"
    echo 
    echo
    echo
    echo -e "$CYAN Whew that was fun, just some reminders. $COL_RESET" 
    echo -e "$RED Your mysql information is saved in ~/.my.cnf. $COL_RESET"
    echo
    echo -e "$RED Yiimp at : http://"$server_name" (https... if SSL enabled)"
    echo -e "$RED Yiimp Admin at : http://"$server_name"/site/AdminPanel (https... if SSL enabled)"
    echo -e "$RED Yiimp phpMyAdmin at : http://"$server_name"/phpmyadmin (https... if SSL enabled)"
    echo
    echo -e "$RED If you want change 'AdminPanel' to access Panel Admin : Edit this file : /var/web/yaamp/modules/site/SiteController.php"
    echo -e "$RED Line 11 => change 'AdminPanel' and use the new address"
    echo
    echo -e "$CYAN Please make sure to change your public keys / wallet addresses in the /var/web/serverconfig.php file. $COL_RESET"
    echo -e "$CYAN Please make sure to change your private keys in the /etc/yiimp/keys.php file. $COL_RESET"
    echo
    echo -e "$CYAN TUTO Youtube : https://www.youtube.com/watch?v=qE0rhfJ1g2k $COL_RESET"
    echo -e "$CYAN Xavatar WebSite : https://www.xavatar.com $COL_RESET"
    echo
    echo
    echo -e "$RED***************************************************$COL_RESET"
    echo -e "$RED YOU MUST REBOOT NOW  TO FINALIZE INSTALLATION !!! $COL_RESET"
    echo -e "$RED***************************************************$COL_RESET"
    echo
    echo
