index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| spath path=username output=user_account

| where action="share_link_create"
    OR action="share_link_access"
    OR action="download"

| eval destination_type=case(
    match(lower(dest_domain),"bytebrew\\.example$"),
        "Internal",

    isnotnull(dest_domain),
        "External",

    true(),
        "Unknown"
)

| stats
    count as events
    values(action) as actions
    values(filename) as files
    values(dest_domain) as destinations
    values(destination_type) as destination_types
    values(share_id) as share_ids
    values(link_label) as link_labels
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user_account

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - events
