Z

index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220"
| search uri="/api/private/export" status_code=200
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
| sort _time
| head 10
