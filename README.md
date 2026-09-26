index="bytebrew"
(
    sourcetype="bytebrew:network_conn"
    OR sourcetype="bytebrew:pos_status"
    OR sourcetype="bytebrew:workstation_sysmon"
)
"192.168.50.18"

| eval net_bytes=if(
    sourcetype="bytebrew:network_conn",
    coalesce(orig_bytes,0)+coalesce(resp_bytes,0),
    0
)

| eval raw_text=lower(_raw)

| eval disconnect=if(
    match(raw_text,"disconnect|offline|connection lost"),
    1,
    0
)

| eval performance=if(
    match(raw_text,"slow|latency|timeout|degraded"),
    1,
    0
)

| eval resource=if(
    match(raw_text,"cpu|memory|disk|resource|utilization"),
    1,
    0
)

| eval error=if(
    match(raw_text,"error|failed|failure|warning|critical"),
    1,
    0
)

| bin _time span=5m

| stats
    count(eval(sourcetype="bytebrew:network_conn")) as network_connections
    count(eval(sourcetype="bytebrew:pos_status")) as pos_events
    count(eval(sourcetype="bytebrew:workstation_sysmon")) as workstation_events
    sum(net_bytes) as network_bytes
    sum(disconnect) as disconnects
    sum(performance) as performance_events
    sum(resource) as resource_events
    sum(error) as errors
    by _time

| eval network_MB=round(network_bytes/1024/1024,2)

| sort - network_MB

| head 10


__________________



index="bytebrew"
| search sourcetype="bytebrew:web_access"

| stats
    count as requests
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code=401 OR status_code=403)) as denied
    count(eval(status_code>=500)) as server_errors
    avg(request_body_len) as avg_request_body
    max(request_body_len) as max_request_body
    avg(response_body_len) as avg_response_body
    max(response_body_len) as max_response_body
    values(method) as methods
    values(user_agent) as user_agents
    values(notes) as notes
    by id.orig_h uri

| where server_errors>0
    OR denied>0
    OR max_request_body>1000

| eval success_pct=round(
    (responses_2xx/requests)*100,
    1
)

| sort - server_errors - max_request_body - requests

| head 30


