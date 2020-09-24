# The following customisations where necessary for a fork of BITCOIN v0.20.
If this helps you with getting your coin up and running please consider a small donation (greatfully received):  
BTC Donation : 3AUJNozgpk2LFiJA4hSqzLqeZvgfVRtdXd  
ETH Donation : 0x7270e7f5de395c630cee546c6661dc0d56886f2e  

## this is due to RPC changes and Segwit activation.
**Important:**  
Bitcoin core and any forked coins using v0.18+ must run xxxxcoind with -addresstype=legacy switch.  
Mining with BECH32 segwit addresses is not yet possible you must generate a legacy address for the pool and your miners to use.  
You do not need to run –deprecatedrpc=accounts and in 0.20 its now removed.  
In YIMMP coin configuration you just need to enable/disable the following:  
-Has Getinfo --- NO  
-Has submitblock --- YES  
-Txmessage --- NO  
-Use Segwit --- YES  
-Type of work --- POW

# CUSTOMISED YIIMP FILES
## STYLE/THEME
- /var/web/yiimp/index.php | customising the look and feel of console with coin logos and headers
- /var/web/yaamp/modules/site/index.php | customising the look and feel of console with coin logos and headers
- /var/web/yaamp/ui/main.php | customising the look and feel of console with coin logos and headers
- /var/web/images/coin-1425.png | custom coin picture

## COIN FIXES (e.g. symbol = XYZ)
- /var/web/yaamp/modules/site/result/wallet_miners_results.php |  adding of worker name | script copies the file from Fixes folder.
- /var/web/yaamp/core/backend/payment.php | line 57 | add your symbol as an extra '||' :  
**|| $coin->symbol == 'XYZ'** 
- /var/web/yaamp/modules/site/coin_results.php | line 300 | add:  
**if ($coin->symbol=="XYZ") $account = "*";**  
  (fixes error 'error -8: label argument must be a valid label')  
  should be just below the line that reads:  
**if ($ETH) $account = $coin->master_wallet;**  
- /web/yaamp/core/backend/coins.php | line 130 | add:  
**if($coin->symbol == 'XYZ')  
            $template = $remote->getblocktemplate('{"rules":["segwit"]}');  
            else**  
should be just above the line that reads:  
**$template = $remote->getblocktemplate('{}');** 
- STRATUM: If you are on Genesis block i.e. height = 0 you must edit coind.cpp in stratum folder and recompile.  
/var/stratum/build/coind.cpp  
**If (!coind->height)**  
// change to  
**if (coind->height<0)**  
// don't forget to revert it back once you've got a couple of blocks mined.

# DISCORD CHANNEL
**Highly useful channel for all things YIMMP: https://discordapp.com/invite/zcCXjkQ**
