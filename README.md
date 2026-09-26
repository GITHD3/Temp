A


index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220" uri="/api/private/export"
| stats
    count as requests
    avg(resp_bytes) as avg_response_bytes
    min(resp_bytes) as min_response_bytes
    max(resp_bytes) as max_response_bytes
    sum(resp_bytes) as total_response_bytes
    values(notes) as notes
    values(user_agent) as user_agents
    by status_code method
| eval avg_response_bytes=round(avg_response_bytes,1)
| sort status_code


index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220" uri="/api/private/export"
| eval denied_time=if(
    status_code=401 OR status_code=403,
    _time,
    null()
)
| eval success_time=if(
    status_code>=200 AND status_code<300,
    _time,
    null()
)
| stats
    count as total_events
    count(eval(status_code=401 OR status_code=403)) as denied_requests
    count(eval(status_code>=200 AND status_code<300)) as success_2xx
    min(denied_time) as first_denied
    max(denied_time) as last_denied
    min(success_time) as first_success
    max(success_time) as last_success
    values(status_code) as status_codes
    values(method) as methods
| convert
    ctime(first_denied)
    ctime(last_denied)
    ctime(first_success)
    ctime(last_success)
