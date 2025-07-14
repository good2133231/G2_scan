./subfinder -dL url -all -o log/passive.txt
./puredns bruteforce file/config/subdomains.txt -d url -r file/config/resolvers.txt -w log/brute.txt
cat log/passive.txt log/brute.txt | sort -u > log/domain_life
./puredns resolve log/domain_life -r file/config/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000  -w log/httpx_url
./httpx -l log/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o log/result_all.json
python start.py
