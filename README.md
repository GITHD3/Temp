index="bytebrew" sourcetype="bytebrew:file_share_audit"
| search dest_domain="suspicious-transfer.example"
| table
    _time
    username
    action
    filename
    dest_domain
    share_id
    link_label
    notes
| sort _time
