index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| eval account=coalesce(
    customer_username,
    username,
    user,
    account
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

| where account="jordan.lee"

| eval evidence_type=case(
    sourcetype="bytebrew:loyalty_audit",
        "Loyalty activity",

    sourcetype="bytebrew:auth_audit",
        "Authentication",

    true(),
        "Other"
)

| eval export_event=if(
    sourcetype="bytebrew:loyalty_audit"
    AND (
        activity="export_prepare"
        OR activity="export_complete"
    ),
    1,
    0
)

| eval login_success=if(
    sourcetype="bytebrew:auth_audit"
    AND (
        activity="login_success"
        OR activity="sso_success"
    ),
    1,
    0
)

| stats
    count as total_events
    sum(export_event) as export_events
    sum(login_success) as successful_auth_events
    values(activity) as activities
    values(result) as results
    values(source_ip) as source_ips
    values(data_scope) as data_scope
    values(export_id) as export_ids
    values(notes) as notes
    values(debug_blob) as debug_blob
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by evidence_type

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort evidence_type
