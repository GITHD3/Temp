index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"

| eval destination=coalesce(
    dest_domain,
    "No destination"
)

| eval destination_type=case(
    destination="No destination",
        "No destination",

    match(
        lower(destination),
        "(^|\\.)bytebrew\\.example$"
    ),
        "Internal ByteBrew",

    true(),
        "External"
)

| eval share_action=if(
    action="share_link_create"
    OR action="share_link_access"
    OR action="download"
    OR action="upload",
    1,
    0
)

| where
    destination_type="External"
    OR share_action=1

| stats
    count as events
    values(action) as actions
    values(filename) as files
    values(dest_domain) as destinations
    values(share_id) as share_ids
    values(link_label) as link_labels
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - events
