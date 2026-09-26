CCC


index="bytebrew"
| search sourcetype="bytebrew:loyalty_audit"

| eval note=lower(coalesce(notes,""))

| where NOT match(
    note,
    "^(normal_|routine_|background_)"
)

| table
    _time
    loyalty_id
    customer_id
    account
    username
    action
    source_ip
    src_ip
    client_ip
    notes
    _raw

| sort _time
