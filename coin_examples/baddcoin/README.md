# The following customisations where necessary for a fork of BITCOIN.

#######CUSTOMISED YIIMP FILES ###################
* STYLE/THEME
- /var/web/yiimp/index.php | customising the look and feel of console with coin logos and headers
- /var/web/yaamp/modules/site/index.php | customising the look and feel of console with coin logos and headers
- /var/web/yaamp/ui/main.php | customising the look and feel of console with coin logos and headers
- /var/web/images/coin-1425.png | custom coin picture

* COIN FIXES
- /var/web/yaamp/modules/site/result/wallet_miners_results.php |  adding of worker name | script copies the file from Fixes folder.
- /var/web/yaamp/core/backend/payment.php | line 57 | add your symbol as an extra '||' :  
**|| $coin->symbol == 'XXX'** 
- /var/web/yaamp/modules/site/coin_results.php | line 300 | add:  
**if ($coin->symbol=="XXX") $account = "*";**  
  (fixes error 'error -8: label argument must be a valid label')  
  should be just below the line that reads:  
**if ($ETH) $account = $coin->master_wallet;**  
- /web/yaamp/core/backend/coins.php | line 130 | add:  
**if($coin->symbol == 'EMC2')  
            $template = $remote->getblocktemplate('{"rules":["segwit"]}');  
            else**  
should be just above the line that reads:  
**$template = $remote->getblocktemplate('{}');** 


