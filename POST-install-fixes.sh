#!/bin/bash
sudo cp fixes/wallet_miners_results.php /var/web/yaamp/modules/site/results/
sudo cp fixes/rc.local /var/stratum/

#restart NGINX
sudo service nginx restart
