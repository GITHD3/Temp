index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search _raw="*liam.brooks*"

| table
    _time
    user
    username
    account
    actor
    action
    operation
    file_name
    filename
    file
    path
    dest_ip
    destination_ip
    remote_ip
    bytes
    bytes_sent
    file_size
    transfer_size
    notes
    _raw

| sort _time
| head 30
