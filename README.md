L



index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| fillnull value="No note" notes

| where NOT match(
    lower(notes),
    "^normal_|^routine_"
)

| eval account=coalesce(
    loyalty_id,
    account,
    username,
    user,
    customer_id,
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

| table
    _time
    sourcetype
    account
    source_ip
    activity
    notes

| sort _time
