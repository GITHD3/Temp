D

index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220"
| search uri="/api/private/export"
| eval success_flag=if(status_code>=200 AND status_code<300,1,0)
| where success_flag=1
| table
    _time
    host
    id.orig_h
    method
    uri
    status_code
    status_msg
    resp_bytes
    request_body_len
    user_agent
    notes
| sort 0 _time
| head 10

index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220"
| search uri="/api/private/export"
| table
    _time
    host
    id.orig_h
    method
    uri
    status_code
    status_msg
    resp_bytes
    request_body_len
    user_agent
    notes
| sort 0 _time
| head 30
