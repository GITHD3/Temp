index="bytebrew"
| search sourcetype="bytebrew:auth_audit"
| search "jordan.lee" OR "10.20.20.21"
| table
    _time
    username
    user
    account
    source_ip
    src_ip
    action
    result
    notes
| sort _time
