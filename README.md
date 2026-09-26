C


index="bytebrew"
sourcetype="bytebrew:mail_audit"

| fieldsummary

| where match(
    field,
    "(?i)sender|from|recipient|to|mail|subject|spf|dkim|dmarc|auth|source|src|ip|reply|return|domain"
)

| table
    field
    count
    distinct_count
    min
    max
    values

| sort field


______



index="bytebrew"
| search sourcetype="bytebrew:web_access"

| bin _time span=5m

| stats
    count as total_requests
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code>=400 AND status_code<500)) as responses_4xx
    count(eval(status_code>=500)) as responses_5xx
    count(eval(status_code=503)) as responses_503
    dc(id.orig_h) as unique_sources
    values(host) as hosts
    values(uri) as affected_uris
    values(status_code) as status_codes
    values(status_msg) as status_messages
    by _time

| eval success_pct=round(
    (responses_2xx/total_requests)*100,
    1
)

| eval error_pct=round(
    (responses_5xx/total_requests)*100,
    1
)

| where
    responses_5xx>0
    OR responses_503>0

| sort - responses_5xx

| head 30
