ggyg
index="bytebrew"
(
    sourcetype="bytebrew:network_conn"
    OR sourcetype="bytebrew:pos_status"
    OR sourcetype="bytebrew:workstation_sysmon"
)
"192.168.50.18"

| eval network_flag=if(
    sourcetype="bytebrew:network_conn",
    1,
    0
)

| eval pos_flag=if(
    sourcetype="bytebrew:pos_status",
    1,
    0
)

| eval workstation_flag=if(
    sourcetype="bytebrew:workstation_sysmon",
    1,
    0
)

| eval network_bytes=if(
    network_flag=1,
    coalesce(orig_bytes,0)+coalesce(resp_bytes,0),
    0
)

| eval destination=if(
    network_flag=1,
    'id.resp_h',
    null()
)

| eval network_protocol=if(
    network_flag=1,
    coalesce(proto,service),
    null()
)

| eval event_text=lower(_raw)

| eval disconnect_flag=if(
    match(
        event_text,
        "disconnect|disconnected|offline|connection lost"
    ),
    1,
    0
)

| eval performance_flag=if(
    match(
        event_text,
        "slow|latency|timeout|degraded|performance"
    ),
    1,
    0
)

| eval alert_flag=if(
    match(
        event_text,
        "warning|critical|failed|failure|error"
    ),
    1,
    0
)

| bin _time span=5m

| stats
    sum(network_flag) as network_connections
    sum(pos_flag) as pos_events
    sum(workstation_flag) as workstation_events
    sum(network_bytes) as network_bytes
    dc(destination) as unique_destinations
    values(destination) as destinations
    values(network_protocol) as protocols
    sum(disconnect_flag) as disconnects
    sum(performance_flag) as performance_events
    sum(alert_flag) as alerts_errors
    by _time

| eval network_MB=round(
    network_bytes/1024/1024,
    2
)

| eventstats
    avg(network_connections) as avg_connections
    avg(network_MB) as avg_network_MB

| eval connection_ratio=round(
    network_connections/avg_connections,
    1
)

| eval traffic_ratio=round(
    network_MB/avg_network_MB,
    1
)

| sort - network_MB

| head 15





_______________________




index="bytebrew"
| search sourcetype="bytebrew:web_access"

| eventstats
    perc95(request_body_len) as p95_request_body

| eval denied_flag=if(
    status_code=401 OR status_code=403,
    1,
    0
)

| eval success_flag=if(
    status_code>=200 AND status_code<300,
    1,
    0
)

| eval server_error_flag=if(
    status_code>=500,
    1,
    0
)

| eval scripted_flag=if(
    match(
        lower(coalesce(user_agent,"")),
        "python-requests|curl|wget|sqlmap|nikto|scanner"
    ),
    1,
    0
)

| eval sensitive_uri_flag=if(
    match(
        lower(uri),
        "/admin|/api/debug|/api/private|/internal|/config|\\.env|\\.git|backup|server-status"
    ),
    1,
    0
)

| eval large_request_flag=if(
    request_body_len>=p95_request_body
    AND request_body_len>0,
    1,
    0
)

| eval denied_time=if(
    denied_flag=1,
    _time,
    null()
)

| eval success_time=if(
    success_flag=1,
    _time,
    null()
)

| stats
    count as total_requests
    sum(denied_flag) as denied_requests
    sum(success_flag) as responses_2xx
    sum(server_error_flag) as server_errors
    max(scripted_flag) as scripted_client_seen
    max(sensitive_uri_flag) as sensitive_endpoint
    max(large_request_flag) as unusually_large_request
    avg(request_body_len) as avg_request_body
    max(request_body_len) as max_request_body
    avg(response_body_len) as avg_response_body
    max(response_body_len) as max_response_body
    values(status_code) as status_codes
    values(status_msg) as status_messages
    values(method) as methods
    values(tags) as tags
    values(notes) as notes
    values(user_agent) as user_agents
    min(denied_time) as first_denied
    max(denied_time) as last_denied
    min(success_time) as first_success
    max(success_time) as last_success
    by id.orig_h uri

| eval avg_request_body=round(
    avg_request_body,
    1
)

| eval avg_response_body=round(
    avg_response_body,
    1
)

| eval success_pct=round(
    (responses_2xx/total_requests)*100,
    1
)

| eval success_after_denial=if(
    denied_requests>0
    AND responses_2xx>0
    AND last_success>first_denied,
    "Yes",
    "No"
)

| where
    denied_requests>0
    OR server_errors>0
    OR scripted_client_seen=1
    OR sensitive_endpoint=1
    OR unusually_large_request=1

| convert
    ctime(first_denied)
    ctime(last_denied)
    ctime(first_success)
    ctime(last_success)

| sort
    - server_errors
    - denied_requests
    - total_requests

| head 30




