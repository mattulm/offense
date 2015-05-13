#!/bin/bash
#
#

#
# update nikto first.
cd /home/tools/nikto/
git pull

#
# Run Some scans.
cd program
./nikto.pl -e 2 -Tuning 1 -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.t1.nikto
sleep 15;
./nikto.pl -e 4 -Tuning 2 -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.t2.nikto
sleep 15;
./nikto.pl -e 5 -Tuning 3 -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.t3.nikto
sleep 15;
./nikto.pl -e B -Tuning e -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.te.nikto
sleep 15;
./nikto.pl -e 1 -Tuning 5 -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.t5.nikto
sleep 15;
./nikto.pl -e 8 -Tuning 7 -C none -no404 -useragent Mozilla -Display 2 -host $1 >> /home/$1.t7.nikto
sleep 15;
./nikto.pl -C all -e A -useragent Mozilla -IgnoreCode -host $1 >> /home/$1.t7.nikto


