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
./nikto.pl -evasion 2 -Tuning 1 -no404 -useragent Mozilla -host $1 >> /home/$1.t1.nikto
sleep 15;
./nikto.pl -evasion 4 -Tuning 2 -no404 -useragent Mozilla -host $1 >> /home/$1.t2.nikto
sleep 15;
./nikto.pl -evasion 5 -Tuning 3 -no404 -useragent Mozilla -host $1 >> /home/$1.t3.nikto
sleep 15;
./nikto.pl -evasion 3 -Tuning e -no404 -useragent Mozilla -host $1 >> /home/$1.te.nikto
sleep 15;
./nikto.pl -evasion 1 -Tuning 5 -no404 -useragent Mozilla -host $1 >> /home/$1.t5.nikto
sleep 15;
./nikto.pl -evasion 8 -Tuning 7 -no404 -useragent Mozilla -host $1 >> /home/$1.t7.nikto


