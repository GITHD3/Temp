V


index="bytebrew"
| search sourcetype="bytebrew:system_change"

| eval note=lower(coalesce(notes,""))
| eval act=lower(coalesce(action,""))

| where
    isnotnull(change_id)
    OR match(note,"maintenance|planned|scheduled maintenance")
    OR match(act,"patch|upgrade|deploy|maintenance")

| where NOT (
    note="background_normal"
    OR note="routine_operational_event"
    OR note="routine_backup_cycle"
)

| stats
    count as events
    earliest(_time) as start_time
    latest(_time) as end_time
    values(action) as actions
    values(status) as statuses
    values(component) as components
    values(actor_display_name) as actors
    values(notes) as notes
    by change_id

| convert
    ctime(start_time)
    ctime(end_time)

| sort start_time









_______________








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

| eval operation=coalesce(
    action,
    operation,
    event,
    activity,
    event_type
)

| eval destination=coalesce(
    dest_ip,
    destination_ip,
    dst_ip,
    remote_ip,
    external_ip,
    'id.resp_h'
)

| eval transfer_bytes=coalesce(
    bytes,
    file_size,
    size,
    bytes_sent,
    transfer_size,
    0
)

| where user_account="liam.brooks"
    AND transfer_bytes>0

| eval transfer_MB=round(
    transfer_bytes/1024/1024,
    2
)

| table
    _time
    user_account
    operation
    file_asset
    transfer_MB
    destination
    notes
    _raw

| sort - transfer_MB

| head 20




