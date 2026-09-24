index="bytebrew"
| search sourcetype="bytebrew:web_access"
| where in(id.orig_h,
    "45.77.210.24",
    "185.220.101.45",
    "103.27.202.99",
    "198.51.100.220",
    "167.94.138.55",
    "104.131.12.90",
    "89.248.165.44",
    "10.20.20.35",
    "10.20.20.36",
    "10.20.20.41")
| eval denied=if(
    status_code=401 OR status_code=403,
    1,
    0)
| eventstats
    max(denied) as uri_was_denied
    by id.orig_h uri
| where uri_was_denied=1
| stats
    count(eval(status_code=401 OR status_code=403)) as denied_requests
    count(eval(status_code>=200 AND status_code<300)) as success_2xx_same_uri
    dc(uri) as denied_uris
    values(eval(
        if(status_code>=200 AND status_code<300,
        uri,
        null())
    )) as successful_uris
    by id.orig_h
| eval successful_uris=if(
    isnull(successful_uris),
    "None",
    successful_uris)
| sort - denied_requests
