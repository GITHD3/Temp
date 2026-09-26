AA

index="bytebrew"
| search sourcetype="bytebrew:mail_audit"

| spath

| eval sender=coalesce(
    sender,
    from,
    mail_from,
    envelope_from,
    src_user,
    user
)

| eval recipient=coalesce(
    recipient,
    to,
    rcpt_to,
    envelope_to,
    dest_user
)

| eval subject_line=coalesce(
    subject,
    email_subject,
    message_subject,
    "(no subject)"
)

| eval auth_result=coalesce(
    auth_result,
    authentication_result,
    spf_result,
    dkim_result,
    dmarc_result,
    auth_status,
    result
)

| eval source_ip=coalesce(
    src_ip,
    source_ip,
    client_ip,
    ip,
    'id.orig_h'
)

| eval event_text=lower(_raw)

| eval spoof_indicator=if(
    match(
        event_text,
        "spf.*fail|dkim.*fail|dmarc.*fail|spoof|impersonat|forged|authentication.*fail"
    ),
    1,
    0
)

| eval suspicious_subject=if(
    match(
        lower(subject_line),
        "urgent|password|invoice|payment|account|verify|reset|confidential|action required"
    ),
    1,
    0
)

| stats
    count as messages
    dc(recipient) as unique_recipients
    dc(source_ip) as source_ips
    values(recipient) as recipients
    values(source_ip) as source_addresses
    values(auth_result) as authentication_results
    values(subject_line) as subjects
    sum(spoof_indicator) as spoof_indicators
    sum(suspicious_subject) as suspicious_subjects
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by sender

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort
    - spoof_indicators
    - messages



    ___________________




index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search host="order.bytebrew.example"

| bin _time span=5m

| stats
    count as total_requests
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code>=400 AND status_code<500)) as responses_4xx
    count(eval(status_code>=500)) as responses_5xx
    count(eval(status_code=503)) as service_unavailable
    dc(id.orig_h) as unique_sources
    values(status_code) as status_codes
    values(status_msg) as status_messages
    by _time

| eval success_pct=round(
    (responses_2xx/total_requests)*100,
    1
)

| eval server_error_pct=round(
    (responses_5xx/total_requests)*100,
    1
)

| where
    responses_5xx>0
    OR service_unavailable>0
    OR success_pct<50

| sort _time
    
