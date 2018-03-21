# sslScrape
SSLScrape | A scanning tool for scaping hostnames from SSL certificates.
Written by Peter Kim <Author, The Hacker Playbook> and @bbuerhaus
                     <CEO, Secure Planet LLC>

  _________ _________.____       _________                                  
 /   _____//   _____/|    |     /   _____/ ________________  ______   ____  
 \_____  \ \_____  \ |    |     \_____  \_/ ___\_  __ \__  \ \____ \_/ __ \ 
 /        \/        \|    |___  /        \  \___|  | \// __ \|  |_> >  ___/ 
/_______  /_______  /|_______ \/_______  /\___  >__|  (____  /   __/ \___  >
        \/        \/         \/        \/     \/           \/|__|        \/ 

Usage | python sslScrape.py [CIDR Range]
E.X   | python sslScrape.py 10.100.100.0/24
 
Requirements:
pip install ndg-httpsclient
pip install python-masscan
