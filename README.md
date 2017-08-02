# camisade.py
-------------------------------------------------
Automatic Discovery and Banner Grabbing Tool



Available Functions:

-t IP/URL, --target IP/URL    Range or IP to Analyze - Discover open ports and Banner Grabbing 


-d IP/URL, --view IP/URL      The truth is Out there - Discover and detect live machines



Requirements:

1. python-nmap
2. socket
3. scapy
4. Mysql datababase

CREATE TABLE `Banners` (
 `ip_address` varchar(15) NOT NULL,
 `port` varchar(6) NOT NULL,
 `banner` varchar(200) NOT NULL,
 UNIQUE KEY `ip_address` (`ip_address`,`port`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8


dbhost = os.environ['mydbhost']

dbpasswd = os.environ['mydbpasswd']

dbname = os.environ['mydname']

dbuser = os.environ['mydbuser']

