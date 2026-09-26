NN

index="bytebrew"
(
    sourcetype="bytebrew:system_change"
    OR sourcetype="bytebrew:web_access"
)

| eval raw_text=lower(_raw)

| eval maintenance_flag=if(
    sourcetype="bytebrew:system_change"
    AND match(
        raw_text,
        "maintenance|scheduled|patch|upgrade|deploy|restart|change"
    ),
    1,
    0
)

| eval suspicious_change=if(
    sourcetype="bytebrew:system_change"
    AND match(
        raw_text,
        "failed|failure|unauthorised|unauthorized|unexpected|critical|rollback"
    ),
    1,
    0
)

| eval web_2xx=if(
    sourcetype="bytebrew:web_access"
    AND status_code>=200
    AND status_code<300,
    1,
    0
)

| eval web_5xx=if(
    sourcetype="bytebrew:web_access"
    AND status_code>=500,
    1,
    0
)

| eval web_503=if(
    sourcetype="bytebrew:web_access"
    AND status_code=503,
    1,
    0
)

| bin _time span=5m

| stats
    sum(maintenance_flag) as maintenance_events
    sum(suspicious_change) as suspicious_change_events
    sum(web_2xx) as successful_requests
    sum(web_5xx) as server_errors
    sum(web_503) as service_unavailable
    values(change_id) as change_ids
    values(action) as actions
    values(status) as change_status
    values(component) as components
    values(notes) as notes
    values(host) as affected_hosts
    by _time

| eval total_web_requests=
    successful_requests+server_errors

| eval error_pct=if(
    total_web_requests>0,
    round((server_errors/total_web_requests)*100,1),
    null()
)

| where
    maintenance_events>0
    OR suspicious_change_events>0
    OR server_errors>0

| sort _time


______________




index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"

| spath

| eval user_account=coalesce(
    user,
    username,
    account,
    actor,
    actor_name,
    src_user
)

| eval file_asset=coalesce(
    file_name,
    filename,
    file,
    object,
    object_name,
    path,
    file_path
)

| eval destination_ip=coalesce(
    dest_ip,
    destination_ip,
    dst_ip,
    remote_ip,
    external_ip,
    'id.resp_h'
)

| eval operation=coalesce(
    action,
    operation,
    event,
    activity,
    event_type
)

| eval transfer_bytes=coalesce(
    bytes,
    file_size,
    size,
    bytes_sent,
    transfer_size,
    0
)

| eval destination_type=case(
    cidrmatch("10.0.0.0/8",destination_ip),
        "Internal",

    cidrmatch("172.16.0.0/12",destination_ip),
        "Internal",

    cidrmatch("192.168.0.0/16",destination_ip),
        "Internal",

    isnotnull(destination_ip),
        "External/Other",

    true(),
        "Unknown"
)

| stats
    count as events
    sum(transfer_bytes) as total_bytes
    values(operation) as operations
    values(file_asset) as files
    values(destination_ip) as destinations
    values(destination_type) as destination_types
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user_account

| eval total_MB=round(
    total_bytes/1024/1024,
    2
)

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - total_bytes - events

