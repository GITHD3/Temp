D


index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="45.77.210.24"
    OR id.orig_h="185.220.101.45"
    OR id.orig_h="103.27.202.99"
    OR id.orig_h="198.51.100.220"
    OR id.orig_h="167.94.138.55"
    OR id.orig_h="104.131.12.90"
    OR id.orig_h="89.248.165.44"
    OR id.orig_h="10.20.20.35"
    OR id.orig_h="10.20.20.36"
    OR id.orig_h="10.20.20.41"
| eval denied=if(status_code=401 OR status_code=403,1,0)
| eventstats
    max(denied) as was_denied
    by id.orig_h uri
| where was_denied=1
| stats
    count(eval(status_code=401 OR status_code=403)) as denied_requests
    count(eval(status_code>=200 AND status_code<300)) as success_2xx
    values(status_code) as status_codes
    values(method) as methods
    by id.orig_h uri
| where success_2xx>0
| sort - success_2xx
