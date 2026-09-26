SD



index="bytebrew"
sourcetype="bytebrew:web_access"
| eval activity_note=coalesce(notes,"No note")
| stats
    count as events
    dc(id.orig_h) as source_ips
    dc(uri) as unique_uris
    values(status_code) as status_codes
    values(method) as methods
    values(uri) as sample_uris
    values(user_agent) as user_agents
    by activity_note
| sort - events



SD2


index="bytebrew"
sourcetype="bytebrew:network_conn"
"192.168.50.18"
| fieldsummary
| where match(
    field,
    "(?i)byte|packet|orig|resp|src|dest|id\\.|proto|service"
)
| table
    field
    count
    distinct_count
    min
    max
    values
| sort field
