#!/bin/bash

echo "1. Total requests:"
wc -l < apache_logs

echo -e "\n1.1 GET requests:"
grep -c '"GET ' apache_logs

echo -e "\n1.2 POST requests:"
grep -c '"POST ' apache_logs

echo -e "\n2. Total unique IPs:"
awk '{print $1}' apache_logs | sort -u | wc -l

echo -e "\n2.1 GET and POST requests per IP:"
awk '{print $1, $6}' apache_logs | sed 's/"//g' | grep -E 'GET|POST' | sort | uniq -c

echo -e "\n3. Failed requests (4xx/5xx):"
awk '$9 ~ /^[45]/' apache_logs | wc -l

echo -e "\n3.1 Percentage of failed requests:"
awk 'BEGIN{t=0;f=0} {t++} $9 ~ /^[45]/ {f++} END {printf "%.2f%%\n", (f/t)*100}' apache_logs

echo -e "\n4. Most active IP:"
awk '{print $1}' apache_logs | sort | uniq -c | sort -nr | head -1

echo -e "\n5. Average requests per day:"
awk '{print $4}' apache_logs | cut -d: -f1 | tr -d '[' | sort | uniq -c | awk '{s+=$1; n++} END {print int(s/n)}'

echo -e "\n6. Day with most failures:"
awk '$9 ~ /^[45]/ {gsub("\\[","",$4); split($4,a,":"); print a[1]}' apache_logs | sort | uniq -c | sort -nr | head -5

echo -e "\n7. Requests by hour:"
awk '{split($4,a,":"); print a[2]}' apache_logs | sort | uniq -c | sort -k2n

echo -e "\n8. Request trends by hour:"
awk '{split($4,a,":"); print a[2]}' apache_logs | sort | uniq -c | sort -k2n

echo -e "\n9. Status code breakdown:"
awk '{print $9}' apache_logs | sort | uniq -c | sort -nr

echo -e "\n10. Most active IP by GET/POST method:"
awk '{print $1, $6}' apache_logs | sed 's/"//g' | grep -E 'GET|POST' | sort | uniq -c | sort -nr | head -1

echo -e "\n11. Failure patterns by hour:"
awk '$9 ~ /^[45]/ {split($4,a,":"); print a[2]}' apache_logs | sort | uniq -c | sort -nr
