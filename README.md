index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search dest_domain="suspicious-transfer.example"
| spath path=username output=user_account

| table
    _time
    user_account
    action
    filename
    dest_domain
    share_id
    link_label
    notes

| sort _time
