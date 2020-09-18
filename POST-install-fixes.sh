#!/bin/bash
sudo cp fixes/wallet_miners_results.php /var/web/yaamp/modules/site/results/

#restart NGINX
sudo service nginx restart
