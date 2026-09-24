# Temp
Not Important


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
| iplocation id.orig_h
| eval Country=coalesce(Country,
        if(cidrmatch("10.0.0.0/8",id.orig_h),"Private/Internal","Unmapped"))
| stats count as total_requests
        count(eval(status_code=401 OR status_code=403)) as unauthorized
        count(eval(status_code>=200 AND status_code<300)) as responses_2xx
        dc(uri) as unique_uris
        values(method) as methods
        values(notes) as notes
        by id.orig_h Country
| eval unauthorized_pct=round((unauthorized/total_requests)*100,1)
| sort - unauthorized
