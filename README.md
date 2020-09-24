*****************************************************************************************************
# Yiimp_install_scrypt v1.1 (update SynergyTCS, 2020)

Site : https://pool.baddcoin.org

https://github.com/synergytcs/yiimp_install_scrypt


*****************************************************************************************************
With great thanks to the original authors for all the heavy lifting.

CODE HISTORY:
- The original base by TPRUVOT: https://github.com/tpruvot/yiimp)
- The fork used in this script for Yiimp Installation: https://github.com/devaultcrypto/yiimp.git
- Modified Yiimp Installer based on the multipool Yiimp Installer: 
https://github.com/cryptopool-builders/multipool_original_yiimp_installer
*****************************************************************************************************

## Install script for yiimp on Ubuntu Server 18.04

###### :bangbang: **IMPORTANT** : 
- USE THIS SCRIPT ON FRESH INSTALL UBUNTU Server 18.04 -- do not use 20.x or 16.04! -- do not use root
- INSTALL YIIMP **BEFORE** INSTALLING YOUR COIN DEAMON & DEPENDENCIES


Create your Pool user account:
- adduser mypooluser
- adduser mypooluser sudo
- usermod -a -G sudo mypooluser

Prepare the environment and clone the git repositories:
Run the debug version of the installer:
- sudo apt update & apt upgrade -y
- reboot
- su - mypooluser
- sudo apt -y install git
- sudo git clone https://github.com/synergytcs/yiimp_install_scrypt
- cd yiimp_install_scrypt/
- sudo chmod +x install-debug.sh
- ./install_debug.sh (DO NOT RUN THE SCRIPT AS ROOT or SUDO)
- At the end, you MUST REBOOT to finalise installation...

Finish !
- Go http://xxx.xxx.xxx.xxx or https://xxx.xxx.xxx.xxx (if you have chosen LetsEncrypt SSL). Enjoy !
- Go http://xxx.xxx.xxx.xxx/site/AdminPanel or https://xxx.xxx.xxx.xxx/site/AdminPanel to access Panel Admin


###### :bangbang: ** CUSTOMISE THE FOLLOWING FILES :**
- **/var/web/serverconfig.php :** update this file to include your public ip (line = YAAMP_ADMIN_IP) to access the admin panel (Put your PERSONAL IP, NOT the IP of your VPS). update with public keys from exchanges. update with other information specific to your server..
- **/etc/yiimp/keys.php :** update with secrect keys from the exchanges (not mandatory)
- **If you want change 'AdminPanel' to access Panel Admin :** Edit this file "/var/web/yaamp/modules/site/SiteController.php" and Line 11 => change 'AdminPanel'


###### :bangbang: **IMPORTANT** : 

- The configuration of yiimp is through the web console and isn't too challenging. 
- Backend code changes are normally required for cloned coins to function (yiimp + stratum + blocknotify) and requires detailed knowledge of linux and the crypto core releases chosen, particularly around the supported rpc objects.
- Your mysql information (login/Password) is saved in **~/.my.cnf**

***********************************

###### This script is interactive thus will ask you for the following information :

- Server Name (no http:// no www !!!!! Example : crypto.com OR pool.crypto.com OR 80.41.52.63)
- Are you using a subdomain (mypoolx11.crypto.com)
- Enter support email
- Set stratum to AutoExchange
- Your Public IP for admin access (Put your PERSONAL IP, NOT IP of your VPS - go to google and search 'my ip')
- Install Fail2ban
- Install UFW and configure ports
- Install LetsEncrypt SSL
- Optional remove all the pre-configured coins

***********************************

**This install script will get you 95% ready to go with yiimp. There are a few things you need to do after the main install is finished.**

Whilst every contributer has no doubt added server security enhancements to the script, it is still every server owner's responsibility to fully secure their environment. 

After the installation you will still need to customise your serverconfig.php file to your liking, add your API keys, and build/add your coins to the control panel. 

If you did not chose the option to remove default coins there will be a long list of coins visible in the console. These have nothing to do with the installation script and are from the database import from the yiimp github. 

If you need further assistance there is a thriving community on discord -- feel free to join this discord channel at https://discordapp.com/invite/zcCXjkQ

If this helped you please consider the original developers and donate to their addresses.
These guys did all the heavy lifting.
(above links)

If my version helped you please also consider my input:
- BTC Donation : 3AUJNozgpk2LFiJA4hSqzLqeZvgfVRtdXd
- ETH Donation : 0x7270e7f5de395c630cee546c6661dc0d56886f2e
