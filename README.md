index="bytebrew"
| search sourcetype="bytebrew:auth_audit"
| search "jordan.lee" OR "10.20.20.21"
| stats
    count as events
    values(action) as actions
    values(result) as results
    values(src_ip) as source_ips
    values(notes) as notes
    by username
| sort - events
