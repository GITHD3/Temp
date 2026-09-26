index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search action="share_link_create"
    OR action="share_link_access"
    OR action="download"
    OR action="upload"

| stats
    count as events
    values(filename) as files
    values(dest_domain) as destinations
    values(share_id) as share_ids
    values(link_label) as link_labels
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user action

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - events
