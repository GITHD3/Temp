V


index="bytebrew" sourcetype="bytebrew:network_conn"
| search id.orig_h="192.168.50.18"

| eval total_bytes=
    coalesce(orig_bytes,0)
    +
    coalesce(resp_bytes,0)

| bin _time span=5m

| stats
    count as connections
    sum(total_bytes) as total_bytes
    dc(id.resp_h) as unique_destinations
    values(id.resp_h) as destinations
    values(proto) as protocols
    values(service) as services
    by _time

| eval traffic_MB=round(
    total_bytes/1024/1024,
    2
)

| sort - traffic_MB

| head 20




BN




index="bytebrew" sourcetype="bytebrew:web_access"

| fieldsummary

| where match(
    field,
    "(?i)uri|query|body|payload|param|request|post|form|arg|refer|user.agent|note"
)

| table
    field
    count
    distinct_count
    min
    max
    values

| sort field
