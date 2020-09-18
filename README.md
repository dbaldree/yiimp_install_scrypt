*****************************************************************************************************
# Yiimp_install_scrypt v1.1 (update SynergyTCS, 2020)

Site : https://pool.baddcoin.org

Discord : T.B.C.

Official Yiimp (used in this script for Yiimp Installation): https://github.com/tpruvot/yiimp
Modified Yiimp Installer (used in this script): https://github.com/xavatar/yiimp_install_scrypt.git
Original Yiimp Installer : https://github.com/cryptopool-builders/multipool_original_yiimp_installer
*****************************************************************************************************

## Install script for yiimp on Ubuntu Server 18.04 (use Tpruvot's Yiimp)

USE THIS SCRIPT ON FRESH INSTALL UBUNTU Server 18.04 !

Connect on your VPS =>
- apt update
- apt upgrade
- reboot
- adduser pool (pool it's just an example...)
- adduser pool sudo
- su - pool
- sudo apt -y install git
- git clone https://github.com/xavatar/yiimp_install_scrypt.git
- cd yiimp_install_scrypt/
- bash install.sh (DO NOT RUN THE SCRIPT AS ROOT or SUDO)
- At the end, you MUST REBOOT to finalize installation...

Finish !
- Go http://xxx.xxx.xxx.xxx or https://xxx.xxx.xxx.xxx (if you have chosen LetsEncrypt SSL). Enjoy !
- Go http://xxx.xxx.xxx.xxx/AdminPanel or https://xxx.xxx.xxx.xxx/AdminPanel to access Panel Admin

If you are issue after installation (nginx,mariadb... not found), use this script : bash install-debug.sh (watch the log during installation)

###### :bangbang: **Kudaraidee Install Script :**
- Instead Tpruvot's Yiimp, you can use the Kudaraidee's Repo Yiimp : git clone -b Kudaraidee https://github.com/Kudaraidee/yiimp.git
- It's an updated Yiimp, with more algo, some fix....

###### :bangbang: **YOU MUST UPDATE THE FOLLOWING FILES :**
- **/var/web/serverconfig.php :** update this file to include your public ip (line = YAAMP_ADMIN_IP) to access the admin panel (Put your PERSONNAL IP, NOT IP of your VPS). update with public keys from exchanges. update with other information specific to your server..
- **/etc/yiimp/keys.php :** update with secrect keys from the exchanges (not mandatory)
- **If you want change 'AdminPanel' to access Panel Admin :** Edit this file "/var/web/yaamp/modules/site/SiteController.php" and Line 11 => change 'AdminPanel'


###### :bangbang: **IMPORTANT** : 

- The configuration of yiimp and coin require a minimum of knowledge in linux
- Your mysql information (login/Password) is saved in **~/.my.cnf**

***********************************

###### This script has an interactive beginning and will ask for the following information :

- Server Name (no http:// or www !!!!! Example : crypto.com OR pool.crypto.com OR 80.41.52.63)
- Are you using a subdomain (mypoolx11.crypto.com)
- Enter support email
- Set stratum to AutoExchange
- Your Public IP for admin access (Put your PERSONNAL IP, NOT IP of your VPS)
- Install Fail2ban
- Install UFW and configure ports
- Install LetsEncrypt SSL

***********************************

**This install script will get you 95% ready to go with yiimp. There are a few things you need to do after the main install is finished.**

While I did add some server security to the script, it is every server owners responsibility to fully secure their own servers. After the installation you will still need to customise your serverconfig.php file to your liking, add your API keys, and build/add your coins to the control panel. 

There will be several wallets already in yiimp. These have nothing to do with the installation script and are from the database import from the yiimp github. 

If you need further assistance we have a small but growing discord channel at https://discord.gg/T.B.C.

If this helped you please consider the original developers and donate to their addresses.
These guys did all the heavy lifting.
(above links)

If my version helped you please also consider my input:
- BTC Donation : 3AUJNozgpk2LFiJA4hSqzLqeZvgfVRtdXd
- ETH Donation : 0x7270e7f5de395c630cee546c6661dc0d56886f2e
