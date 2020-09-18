#!/bin/bash
sudo cp Fixes/wallet_miners_results.php /var/web/yaamp/modules/site/results/
sudo cp Fixes/rc.local /var/stratum/
sudo echo ". /var/stratum/rc.local" >> /etc/rc.local

#restart NGINX
sudo service nginx restart
