#!/bin/sh
## Tool :: cdncheck
## Description :: take results and scan for the CDN information.
## Global Variables
d=$(date +"%Y%m%d")
t=$(date +"%H%M")
##
##
## Create the files we need to run our scanner
## We are going to use the output from the httpx scanner
cd /tmp; sleep 1; echo "";
##
##
help () {
	echo "Use -d along with a single domain name"
	echo "Use -f for a file containing domain names"
}

lookup () {
	domain=$1
	retval=0
	output=$(dig -t TXT _dmarc."$domain")

	if [ -n "$(echo "$output" | egrep "\;[^s]*p[s]*\s*=\s*reject\s*")" ];then
		echo "$domain is NOT vulnerable"
	elif [ -n "$(echo "$output" | egrep "\;[^s]*p[s]*\s*=\s*quarantine\s*")" ];then
		echo "$domain can be vulnerable (email will be sent to spam)"
	elif [ -n "$(echo "$output" | egrep "\;[^s]*p[s]*\s*=\s*none\s*")" ];then
		echo "$domain is Vulnerable "
		retval=1
	else
		echo "$domain is vulnerable (No DMARC record found) "
		retval=1
	fi
	return $retval
}

lookfile () {
	input=$1
	counter=0
	vuln=0 

	while IFS= read -r line
		do
			counter=$((counter=counter+1))
			lookup $line >> report.txt
			vuln=$((vuln=vuln+$?))
		done < $input
		echo "\n"
		echo "$vuln out of $counter domains are vulnerable "

	echo "domain, status, reason " >> dmarc.mx.$d.$t.$s.csv
	cat report.txt | sed 's/ is /, /g'| sed 's/ can be /, maybe/g' | sed 's/(/, /g' | sed 's/)//g' >> dmarc.mx.$d.$t.$s.csv
	dos2unix dmarc.mx.$d.$t.$s.csv; 
	mv dmarc.mx.$d.$t.$s.csv /asm/output/dmarc/
}

main () {

	while getopts d:f: flag
	do
		case "${flag}" in
			f) file=${OPTARG};;
			d) domain=${OPTARG};;
		esac
	done

	if [ -n "$domain" ]; then
		lookup $domain
	elif [ -f "$file" ]; then
		lookfile $file
	else
		help
	fi
}


if [ $# != 2  ];then
	echo "Wrong execution\n"
	help
	exit 0
fi

main $@

notvuln=$(cat report.txt | grep "NOT vulnerable" | wc -l)
quarant=$(cat report.txt | grep "can be vulnerable" | wc -l)
vulnera=$(cat report.txt | grep "Vulnerable" | wc -l)
nodmarc=$(cat report.txt | grep "No DMARC" | wc -l)

echo " These are the final results "
echo " Total domains .... $counter "
echo " Not Vulnerable ... $notvuln "
echo " Could Be ......... $quarant "
echo " Vulnerable ....... $vulnera "
echo " Vuln (No DMARC) .. $nodmarc "

rm -rf report.txt
#
##
