K

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
| search status_code=401 OR status_code=403
| bin _time span=1m
| stats
    count as denied_per_minute
    dc(uri) as targets_per_minute
    by id.orig_h _time
| stats
    sum(denied_per_minute) as total_denied
    max(denied_per_minute) as peak_denied_per_minute
    avg(denied_per_minute) as avg_denied_per_active_minute
    max(targets_per_minute) as max_targets_in_one_minute
    dc(_time) as active_minutes
    by id.orig_h
| eval avg_denied_per_active_minute=round(avg_denied_per_active_minute,1)
| sort - total_denied
