W

index="bytebrew"
| search sourcetype="bytebrew:web_access"

| spath

| eval request_text=lower(
    coalesce(uri,"")
    ." ".
    coalesce(query,"")
    ." ".
    coalesce(uri_query,"")
    ." ".
    coalesce(request_body,"")
    ." ".
    coalesce(body,"")
    ." ".
    coalesce(payload,"")
    ." ".
    coalesce(params,"")
    ." ".
    coalesce(notes,"")
)

| eval exploit_type=case(

    match(
        request_text,
        "union.{0,50}select|select.{0,50}from|information_schema|or.{0,20}1=1|sleep\\(|benchmark\\(|%27.{0,30}or"
    ),
    "SQL Injection",

    match(
        request_text,
        "<script|%3cscript|javascript:|onerror=|onload=|alert\\(|%3csvg|%3cimg"
    ),
    "Cross-Site Scripting",

    match(
        request_text,
        "\\.\\./|%2e%2e%2f|%252e%252e|/etc/passwd|boot\\.ini"
    ),
    "Path Traversal",

    match(
        request_text,
        "cmd=|exec=|/bin/sh|whoami|powershell|wget.{0,40}http|curl.{0,40}http"
    ),
    "Command Injection",

    true(),
    null()
)

| where isnotnull(exploit_type)

| eval exploit_2xx=if(
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

| eval server_error=if(
    status_code>=500,
    1,
    0
)

| stats
    count as exploit_attempts
    sum(denied) as denied_attempts
    sum(exploit_2xx) as successful_2xx
    sum(server_error) as server_errors
    values(status_code) as status_codes
    dc(uri) as target_count
    values(uri) as targeted_uris
    values(method) as methods
    values(user_agent) as user_agents
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by id.orig_h exploit_type

| convert
    ctime(first_seen)
    ctime(last_seen)

| eval success_pct=round(
    (successful_2xx/exploit_attempts)*100,
    1
)

| sort - exploit_attempts



____________________




index="bytebrew"
(
    sourcetype="bytebrew:network_conn"
    OR sourcetype="bytebrew:pos_status"
    OR sourcetype="bytebrew:workstation_sysmon"
)
"192.168.50.18"

| spath

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

| eval disconnect_flag=if(
    match(raw_text,"disconnect|disconnected|offline|connection lost"),
    1,
    0
)

| eval performance_flag=if(
    match(raw_text,"slow|latency|timeout|degraded|performance"),
    1,
    0
)

| eval resource_flag=if(
    match(raw_text,"cpu|memory|disk|resource|utilization"),
    1,
    0
)

| eval error_flag=if(
    match(raw_text,"error|failed|failure|warning|critical"),
    1,
    0
)

| bin _time span=5m

| stats
    count(eval(sourcetype="bytebrew:network_conn")) as network_events
    count(eval(sourcetype="bytebrew:pos_status")) as pos_events
    count(eval(sourcetype="bytebrew:workstation_sysmon")) as workstation_events
    sum(traffic_bytes) as traffic_bytes
    dc(peer_ip) as unique_peers
    values(peer_ip) as peers
    values(protocol) as protocols
    sum(disconnect_flag) as disconnects
    sum(performance_flag) as performance_events
    sum(resource_flag) as resource_events
    sum(error_flag) as errors
    by _time

| eval traffic_MB=round(
    traffic_bytes/1024/1024,
    2
)

| sort - traffic_MB

| head 15
