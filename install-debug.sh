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
    echo -e "Removing default coins (except Bitcoin - must leave one) on next boot";
    echo
    # will have to remove the $$$ ones from mysql manually
        # check for rc.local - make one if not present
        FILE="/etc/rc.local";
        if test -f "$FILE"; then
                sudo cp /etc/rc.local /etc/rc.local.backup;
        else
                sudo touch /etc/rc.local;
                sudo chown root:root /etc/rc.local;
        fi

    echo "sudo yiimp coin UNF delete" > /etc/rem_coins.sh
    echo "sudo yiimp coin DES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KUMA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MEME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FOOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UMO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin G3N delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WHIPPED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUMBA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EBG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin I0C delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAPT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PAK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EUC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRE-OLD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CFC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GAME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FONZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DBIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRUMP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JIF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EVIL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EVO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SANDG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RICHX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGCS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOLI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LGBTQ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZOOM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin YOC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SIB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OPES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MMXVI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MBL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AR2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TROLL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DNET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AMS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin INFX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CZECO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EDRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FTP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHAI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin REV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PULSE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CYG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRBIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GMX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HODL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUZZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RBIES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XID delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WARP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CPNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HIRE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XHI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RADS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin X2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HMP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BRONZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RUBIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin REP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CIONZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SCRT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DEUR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VOX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CLUB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SCOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLOZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STATS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HZDOGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BITUSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BITCNY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FNX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin APC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XLM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AGRS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DROP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AMP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ANTI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 1337 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRBO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SOIL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OMNI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CUBE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WOP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FCT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PRT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CBIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NEU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STEPS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PRIME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SWING delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MACRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MAPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ETH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AEON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GSY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHIP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCHC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AXIOM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FUEL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BIOS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IBITS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DIGS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MCZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BANX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CPN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPRTS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPROUT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NUKE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 2BACCO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LFO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VERSA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MCAR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CARB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZUR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VAPE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TALK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RUM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PPCD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PHO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin P0001 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NODE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ISO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HANSA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FX01 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FRSH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIMK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FAIL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CV2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTRHA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ALCUREX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BNX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QUIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin V delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DUO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ANI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MARS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FETISH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BDSM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OFF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHAO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CNO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FUNK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DUCK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BSY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin $MINEZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin $MINEW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin $MINE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FTCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GXG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CIV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TOP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TTY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KIWI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XGR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin $$$ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 66 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DARK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin POP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WSX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin YOVI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HXX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRPS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SJW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GMCX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TENNET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLUS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XRA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TAGR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HAZE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin POLY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin INDEX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GENI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUCKS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPKTR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GENE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DIBS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GTFO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FUTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XVI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLOBE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SMSR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CIRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WOC2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NODX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ERC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SEN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SAK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EOC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRANSF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GEN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRKT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DUB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VAPOR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARPA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BNB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NANAS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SEEDS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OPTION delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLUCK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GREED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MOIN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VCOIN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TWLV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RDN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PSY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ECC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SNRG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CREVA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 32BIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XNA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TWERK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GENIUS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PRE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NICE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CORG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EQM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FADE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SKB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TNG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PTA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MRB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KRAK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin M1 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 16BIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BIT16 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CLV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHELL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LIMX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FSN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TKT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FCS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VTN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PKB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ISL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VIRAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UTLE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GOAT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EPY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CTO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRAV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GPH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TDFB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPHR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GUM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XMS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XSEED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XNX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XTP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DOX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QTZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNAT-skein delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AIB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SIGU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLITZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NIRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HUGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 7 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LUX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UIS-qubit delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UIS-skein delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLING delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin COV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NTRN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CTK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CGN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ACP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 8BIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin P7C delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HZT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LEA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GIZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ETRUST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DECR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RICE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NXE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AECC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PLANET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIRE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ANAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MTLMC3 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TWIST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRIME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KARMA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TCX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TAB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NDOGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GIFT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BBCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRICK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGMS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CCB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OZC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EGG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EKN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MRP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QORA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PXL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin URC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ICN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OCTO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EUR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XEM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLFI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 256 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ICASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCRY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZIRK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRAVE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BITZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PAY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LDOGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RBT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ASN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MINE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XAU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XFC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VOYA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WBB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ECASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MTR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NSR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GSM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PTY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LYB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SUP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CIN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SMAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRID delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGORE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BITB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BEAN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PEN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NVCD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CBX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CELL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KOBO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LQD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XTR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 10K delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MYST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CETI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OMA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XFB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OBS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SOON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GIG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XAP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XUSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin YACC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 1CR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ACH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BELA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin C2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CGA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CNMT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DIEM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DSH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GAP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GDN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GEMZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GOLD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HIRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JLH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MAID delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MIL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MMNXT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MNTA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MRS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NBT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOXT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NXTI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PIGGY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SJCX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SQL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SRCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SWARM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNITY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WOLF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XWC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FSC2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RBR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XBS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin USDT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EAGS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NKA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin INCA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XSP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SBIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UIS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 2015 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ggggg delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UCI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EQX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TAK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TEK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TOR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin USDe delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XJO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XLB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin YAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin YBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ASC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BAT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin COL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CPR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CTM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DBL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ELP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLAP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LEAF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MEM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MEOW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RBBT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TIPS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TIX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZEIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ACOIN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AGS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ALF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ALN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AUR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BEN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BNCR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BQC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CACH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CGB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CINNI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CNL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin COMM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin COOL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRACK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CSC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DEM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DMD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ELC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EMD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EZC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FFC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FRAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FRK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GLYPH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GUE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HBN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ICB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LAB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LGD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LK7 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LKY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTCX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MZC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NAN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NBL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NRB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NRS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NYAN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OSC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PHS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin Points delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PSEUD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PTS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RT2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SAT2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHLD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SILK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SOLE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SSV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EMC2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GIMP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KRYP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MOTO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MSC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NWO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PLCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PROZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SONG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPUDS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SQC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VOXP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VTX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XSX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XVG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FJC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GRN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GUA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HEX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IFC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IRL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KARM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MINT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MOON delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MTLMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NMC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ORB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PAC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PHC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin USD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VTA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BURST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LTCD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRAIG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BSTY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GNS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PXI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MLS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ROS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OPAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXCL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PYRA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SEED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GHC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DOPE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ONE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLEU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CDN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CESC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CLR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CZC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHILD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XQN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RDD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NXT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MYR-qubit delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 888 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EFL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DIME delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WATER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NLG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GIVE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOBL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BITS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin THC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ENRG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHIBE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SFR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NAUT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CURE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SYNC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XSI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDQ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MMXIV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAIX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BBR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HYPER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KTK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MUGA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VOOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XMR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CLOAK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHCC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BURN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KORE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RZR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MIN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TECH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GML delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QTL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XXX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AERO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRUST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BRIT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JUDGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NAV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin APEX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTCD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KEY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NUD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ICG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ESC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PINK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IOC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RAW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MAX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOOM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UNAT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MWC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VAULT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FC2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BIG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ROOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AXR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RIPO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIBRE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SHADE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLEX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XBOT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NKT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CLAM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VTR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SUPER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XPY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SMLY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCENT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FAIR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EVENT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HUC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CAT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RMS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ANC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MONA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SYS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ULTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin METAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CBR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FIND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FUD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ERM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VIA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DEAF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HIC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BAY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VIOR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VPN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EXE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PFC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GSX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BRXv2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ACHK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRYPT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SWIFT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARCH delete" >> /etc/rem_coins.sh    
    echo "sudo yiimp coin GAIA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WWC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XRP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LMR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MNE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CRW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VDO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOPE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XWT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SMBR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HYP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QBK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CENT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLOCK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CATC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SCSY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GUN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ABY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BALLS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QSLV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin U delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BYC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BUN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZNY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MRY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CANN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin POT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TAG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DOGE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RBY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NOTE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 42 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JBS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin J delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SLG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VIK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MARYJ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XMG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RUBLE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XCLD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 007 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BFT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RVN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RFR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LOOM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MFT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BKX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NLC2 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CMCT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TUBE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GTO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NGC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AID delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STORM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BLT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DMT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TUSD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin TRX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCPT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VEE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZRX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WAXP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SRN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IGINS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UKG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ENG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin POWR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VIB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RCN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SALT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MANA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XMY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BSC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SKC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LOG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CHC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FLAX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HEDG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ILM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MYR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CYP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin AMBER delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTQ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HTML5 delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NEOS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XAI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DGB delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MDT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GEO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MUE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SRC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QRK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PXC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin URO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UFO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VTC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin START delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IDC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NXS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RVR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PIVX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STEEM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LSK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LBC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STRAT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ETC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARDR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XZC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NEO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZEC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UBQ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin KMD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ION delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SWT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MLN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ARK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin INCNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GBYTE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EDG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MED delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MOC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZIL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PAX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PAL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PMA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NPXS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XHV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IHT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BOXX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin EDR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DTA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MET delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ENJ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin UPP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HYDRO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IGNIS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BCH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QTUM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PART delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin CVC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin OMG delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ADX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin STORJ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MTL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin FUN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MCO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XEL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DCT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NMR delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin PTOY delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QRL delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin 1ST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ANT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin HMQ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GUP delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DENT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MOBI delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin LBA delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin JNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin USDS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SOLVE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin NCASH delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin XNK delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IOST delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BSV delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ZEN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin GNO delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin RLC delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WINGS delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin MORE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SBD delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin WAVES delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin IOTX delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin VITE delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRGN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTM delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin QNT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin ELF delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTU delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin DRGN delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin BTT delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin SPND delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin \\$\\$\\$ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin \\$""MINEZ delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin \\$""MINEW delete" >> /etc/rem_coins.sh
    echo "sudo yiimp coin \\$""MINE delete" >> /etc/rem_coins.sh
    echo "./etc/rem_coins.sh" >> /etc/rc.local
    echo "cp /etc/rc.local.backup /etc/rc.local" >> /etc/rc.local
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
