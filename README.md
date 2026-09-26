Ca


index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| search auth_result="fail_alignment"

| eval recipient=coalesce(
    recipient,
    to,
    dest_user,
    rcpt_to
)

| eval source_ip=coalesce(
    src_ip,
    source_ip,
    client_ip
)

| table
    _time
    display_from
    from
    recipient
    subject
    auth_result
    source_ip
    dest_ip

| sort _time


______


index="bytebrew"
| search sourcetype="bytebrew:web_access"

| where
    _time>=strptime(
        "2026-04-06 10:20:00",
        "%Y-%m-%d %H:%M:%S"
    )
    AND
    _time<=strptime(
        "2026-04-06 10:50:00",
        "%Y-%m-%d %H:%M:%S"
    )

| bin _time span=5m

| stats
    count as total_requests
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code>=500)) as responses_5xx
    count(eval(status_code=503)) as responses_503
    dc(id.orig_h) as unique_sources
    by _time host

| eval error_pct=round(
    (responses_5xx/total_requests)*100,
    1
)

| eval success_pct=round(
    (responses_2xx/total_requests)*100,
    1
)

| sort _time host
