X


index="bytebrew"
(
    sourcetype="bytebrew:network_conn"
    OR sourcetype="bytebrew:pos_status"
    OR sourcetype="bytebrew:workstation_sysmon"
)
"192.168.50.18"

| eval evidence_source=case(
    sourcetype="bytebrew:network_conn","Network",
    sourcetype="bytebrew:pos_status","POS Status",
    sourcetype="bytebrew:workstation_sysmon","Workstation",
    true(),"Other"
)

| eval source_ip=coalesce(
    id.orig_h,
    src_ip,
    src,
    source_ip,
    client_ip
)

| eval destination_ip=coalesce(
    id.resp_h,
    dest_ip,
    dest,
    destination_ip,
    server_ip
)

| eval protocol=coalesce(
    proto,
    protocol,
    service,
    transport
)

| eval outbound_bytes=coalesce(
    orig_bytes,
    bytes_out,
    bytes_sent,
    src_bytes,
    request_body_len,
    0
)

| eval inbound_bytes=coalesce(
    resp_bytes,
    bytes_in,
    bytes_received,
    dest_bytes,
    0
)

| eval total_bytes=outbound_bytes+inbound_bytes

| eval event_text=lower(_raw)

| eval event_signal=case(
    match(event_text,"disconnect|disconnected|offline"),
        "Disconnect",

    match(event_text,"timeout|timed out|latency|slow|degraded"),
        "Performance",

    match(event_text,"alert|warning|failure|failed|error"),
        "Alert/Error",

    match(event_text,"cpu|memory|disk|resource"),
        "Resource",

    true(),
        "Other"
)

| bin _time span=5m

| stats
    count as events
    sum(total_bytes) as total_bytes
    dc(destination_ip) as unique_destinations
    values(destination_ip) as destinations
    values(protocol) as protocols
    count(eval(event_signal="Disconnect")) as disconnect_events
    count(eval(event_signal="Performance")) as performance_events
    count(eval(event_signal="Alert/Error")) as alert_error_events
    count(eval(event_signal="Resource")) as resource_events
    values(event_signal) as observed_signals
    by _time evidence_source

| eval total_MB=round(total_bytes/1024/1024,2)

| sort _time evidence_source






N




index="bytebrew"
| search sourcetype="bytebrew:web_access"

| eval request_text=lower(
    coalesce(uri,"")
    ." ".
    coalesce(request_body,"")
    ." ".
    coalesce(user_agent,"")
)

| eval attack_type=case(

    match(
        request_text,
        "union(\+|%20| )select|select(\+|%20| ).*from|or(\+|%20| )+1=1|%27|'.*or"
    ),
    "Possible SQL Injection",

    match(
        request_text,
        "<script|%3cscript|javascript:|onerror=|onload="
    ),
    "Possible XSS",

    match(
        request_text,
        "\.\./|%2e%2e%2f|/etc/passwd"
    ),
    "Possible Path Traversal",

    match(
        request_text,
        "cmd=|exec=|/bin/sh|powershell|whoami|%3b"
    ),
    "Possible Command Injection",

    match(
        request_text,
        "\.env|\.git/config|/server-status|/config\.php|backup\.zip|/api/debug|/admin"
    ),
    "Sensitive Endpoint Probing",

    true(),
    null()
)

| eval suspicious=if(
    isnotnull(attack_type),
    1,
    0
)

| eventstats
    max(suspicious) as suspicious_source
    min(eval(if(suspicious=1,_time,null()))) as first_suspicious_time
    by id.orig_h

| where suspicious_source=1

| eval suspicious_success=if(
    suspicious=1
    AND status_code>=200
    AND status_code<300,
    1,
    0
)

| eval suspicious_denied=if(
    suspicious=1
    AND (status_code=401 OR status_code=403),
    1,
    0
)

| eval suspicious_error=if(
    suspicious=1
    AND status_code>=400,
    1,
    0
)

| eval subsequent_2xx=if(
    _time>first_suspicious_time
    AND suspicious=0
    AND status_code>=200
    AND status_code<300,
    1,
    0
)

| eval automated_tool=if(
    match(
        lower(coalesce(user_agent,"")),
        "python-requests|curl|wget|sqlmap|nikto|nmap|scanner"
    ),
    1,
    0
)

| stats
    count as total_source_requests
    sum(suspicious) as suspicious_requests
    sum(suspicious_denied) as denied_suspicious_requests
    sum(suspicious_success) as suspicious_2xx
    sum(suspicious_error) as suspicious_errors
    sum(subsequent_2xx) as subsequent_normal_2xx
    max(automated_tool) as automated_tool_seen
    dc(eval(if(suspicious=1,uri,null()))) as targeted_uri_count
    values(attack_type) as attack_types
    values(eval(if(suspicious=1,uri,null()))) as targeted_uris
    values(method) as methods
    values(user_agent) as user_agents
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by id.orig_h

| convert
    ctime(first_seen)
    ctime(last_seen)

| eval suspicious_success_pct=round(
    (suspicious_2xx/suspicious_requests)*100,
    1
)

| sort - suspicious_requests













