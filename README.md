index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| spath

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

| eval device=coalesce(
    device,
    device_id,
    hostname,
    workstation,
    client
)

| eval activity=coalesce(
    action,
    event,
    operation,
    activity,
    event_type
)

| eval object_data=coalesce(
    data_type,
    field,
    object,
    resource,
    export_type
)

| eval raw_text=lower(_raw)

| eval suspicious_flag=if(
    match(
        raw_text,
        "export|download|leak|unauthor|suspicious|bulk|dump|reset|failed|new device|unusual"
    ),
    1,
    0
)

| stats
    count as total_events
    sum(suspicious_flag) as suspicious_events
    dc(source_ip) as unique_ips
    dc(device) as unique_devices
    values(source_ip) as source_ips
    values(device) as devices
    values(activity) as activities
    values(object_data) as data_types
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by account

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - suspicious_events - total_events
