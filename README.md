index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search action="share_link_create"
    OR action="share_link_access"
    OR action="download"
    OR action="upload"

| eval user_account=coalesce(
    user,
    username,
    actor,
    account,
    "Unknown"
)

| eval file_asset=coalesce(
    filename,
    file_name,
    file,
    "Unknown"
)

| eval destination=coalesce(
    dest_domain,
    destination_domain,
    remote_domain,
    "None recorded"
)

| stats
    count as events
    values(file_asset) as files
    values(destination) as destinations
    values(share_id) as share_ids
    values(link_label) as link_labels
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user_account action

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - events
