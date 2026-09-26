Q



index="bytebrew"
(
    sourcetype="bytebrew:network_conn"
    OR sourcetype="bytebrew:pos_status"
    OR sourcetype="bytebrew:workstation_sysmon"
)
"192.168.50.18"

| eval src_ip=coalesce(
    'id.orig_h',
    src_ip,
    source_ip,
    client_ip,
    src
)

| eval dst_ip=coalesce(
    'id.resp_h',
    dst_ip,
    dest_ip,
    destination_ip,
    server_ip,
    dest
)

| eval peer_ip=case(
    src_ip="192.168.50.18",dst_ip,
    dst_ip="192.168.50.18",src_ip,
    true(),null()
)

| eval protocol=coalesce(
    proto,
    protocol,
    service
)

| eval traffic_bytes=
    coalesce(orig_bytes,0)
    +
    coalesce(resp_bytes,0)

| eval raw_text=lower(_raw)

| eval signal=case(
    match(raw_text,"disconnect|offline|connection lost"),
        "Disconnect",

    match(raw_text,"slow|latency|timeout|degraded"),
        "Performance",

    match(raw_text,"cpu|memory|disk|resource"),
        "Resource",

    match(raw_text,"error|failed|failure|warning"),
        "Error",

    true(),
        "Normal"
)

| bin _time span=5m

| stats
    count as events
    sum(traffic_bytes) as traffic_bytes
    dc(peer_ip) as unique_peers
    values(peer_ip) as peers
    values(protocol) as protocols
    count(eval(signal="Disconnect")) as disconnects
    count(eval(signal="Performance")) as performance_events
    count(eval(signal="Resource")) as resource_events
    count(eval(signal="Error")) as errors
    by _time sourcetype

| eval traffic_MB=round(
    traffic_bytes/1024/1024,
    2
)

| sort - traffic_MB

| head 25





______________________







index="bytebrew"
| search sourcetype="bytebrew:web_access"

| eval request_text=lower(_raw)

| eval exploit_type=case(

    match(
        request_text,
        "union.{0,40}select|select.{0,40}from|information_schema|or.{0,15}1=1|sleep\\(|benchmark\\("
    ),
    "SQL Injection",

    match(
        request_text,
        "<script|%3cscript|javascript:|onerror=|onload=|alert\\(|%3csvg"
    ),
    "Cross-Site Scripting",

    match(
        request_text,
        "\\.\\./|%2e%2e%2f|%252e%252e|/etc/passwd|boot\\.ini"
    ),
    "Path Traversal",

    match(
        request_text,
        "cmd=|exec=|/bin/sh|whoami|powershell|wget|curl.{0,30}http"
    ),
    "Command Injection",

    true(),
    null()
)

| where isnotnull(exploit_type)

| eval successful=if(
    status_code>=200
    AND status_code<300,
    1,
    0
)

| eval denied=if(
    status_code=401
    OR status_code=403,
    1,
    0
)

| stats
    count as exploit_attempts
    sum(denied) as denied_attempts
    sum(successful) as exploit_2xx
    values(status_code) as status_codes
    dc(uri) as target_count
    values(uri) as targeted_uris
    values(method) as methods
    values(user_agent) as user_agents
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by id.orig_h exploit_type

| convert
    ctime(first_seen)
    ctime(last_seen)

| eval success_pct=round(
    (exploit_2xx/exploit_attempts)*100,
    1
)

| sort - exploit_attempts
