S

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
| eval denied_flag=if(status_code=401 OR status_code=403,1,0)
| eval denied_uri=if(status_code=401 OR status_code=403,uri,null())
| bin _time span=1m
| stats
    sum(denied_flag) as denied_per_minute
    dc(denied_uri) as targets_per_minute
    by id.orig_h _time
| where denied_per_minute>0
| stats
    sum(denied_per_minute) as total_denied
    max(denied_per_minute) as peak_denied_per_minute
    avg(denied_per_minute) as avg_denied_per_active_minute
    max(targets_per_minute) as max_targets_in_one_minute
    dc(_time) as active_minutes
    by id.orig_h
| eval avg_denied_per_active_minute=round(avg_denied_per_active_minute,1)
| sort - total_denied




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
| eval success=if(status_code>=200 AND status_code<300,1,0)
| stats
    sum(denied) as denied_requests
    sum(success) as success_2xx
    values(status_code) as status_codes
    values(method) as methods
    by id.orig_h uri
| where denied_requests>0 AND success_2xx>0
| sort - success_2xx
