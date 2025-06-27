./subfinder -dL url -all -o log/passive.txt
puredns bruteforce file/subdomains.txt -d url -r file/resolvers.txt -q -w log/brute.txt
cat log/passive.txt log/brute.txt | sort -u > log/domain_life
puredns resolve log/domain_life -r file/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000 -q -w log/httpx_url
./httpx -l log/httpx_url -mc 200,301,302,403,404 -timeout 2 -tls-probe  -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -json -o log/result_all.json
#python start.py