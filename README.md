n

index="bytebrew"
| search sourcetype="bytebrew:web_access"

| stats
    count as total_requests
    count(eval(status_code=401 OR status_code=403)) as denied
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code>=500)) as server_errors
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
    by id.orig_h uri

| eval scripted=if(
    match(
        lower(mvjoin(user_agents," ")),
        "python-requests|curl|wget|sqlmap|nikto|scanner"
    ),
    1,
    0
)

| eval sensitive=if(
    match(
        lower(uri),
        "/api/private|/api/debug|/internal|/admin|/config|\\.env|\\.git|backup|server-status"
    ),
    1,
    0
)

| where
    denied>0
    OR server_errors>0
    OR scripted=1
    OR sensitive=1

| eval success_pct=round(
    (responses_2xx/total_requests)*100,
    1
)

| sort
    - server_errors
    - denied
    - total_requests

| head 25
