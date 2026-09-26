index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| eval account=coalesce(
    account,
    username,
    user,
    customer_id,
    loyalty_id,
    member_id
)

| eval source_ip=coalesce(
    src_ip,
    source_ip,
    client_ip,
    ip,
    'id.orig_h'
)

| eval activity=coalesce(
    action,
    event,
    operation,
    activity,
    event_type
)

| eval text=lower(
    coalesce(activity,"")
    ." ".
    coalesce(notes,"")
    ." ".
    _raw
)

| eval suspicious=if(
    match(
        text,
        "export|download|bulk|dump|leak|exfil|suspicious|unauthor|unexpected|credential abuse|account takeover"
    ),
    1,
    0
)

| where suspicious=1

| stats
    count as suspicious_events
    values(sourcetype) as evidence_sources
    values(activity) as activities
    values(source_ip) as source_ips
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by account

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - suspicious_events
