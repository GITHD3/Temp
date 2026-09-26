X


index="bytebrew"
| search sourcetype="bytebrew:loyalty_audit"

| eval note=lower(coalesce(notes,""))
| eval act=lower(coalesce(action,""))

| where
    (isnotnull(export_id) AND export_id!="")
    OR isnotnull(data_scope)
    OR match(
        act,
        "export|download|bulk|dump"
    )
    OR match(
        note,
        "leak|exfil|export|bulk|dump|unauthor|suspicious"
    )

| where NOT match(
    note,
    "unusual_but_benign|travel_or_vpn_like|normal_|routine_|background_"
)

| table
    _time
    customer_username
    action
    result
    data_scope
    export_id
    src_ip
    notes
    debug_blob

| sort _time
