dd

index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220"
| search uri="/api/private/export"

| eval result_type=case(
    status_code=401 OR status_code=403,
        "Denied",

    status_code>=200 AND status_code<300,
        "Successful 2xx",

    status_code>=500,
        "Server Error",

    true(),
        "Other"
)

| eval denied_time=if(
    result_type="Denied",
    _time,
    null()
)

| eval success_time=if(
    result_type="Successful 2xx",
    _time,
    null()
)

| stats
    count as total_requests
    count(eval(result_type="Denied")) as denied_requests
    count(eval(result_type="Successful 2xx")) as successful_2xx
    count(eval(result_type="Server Error")) as server_errors
    values(status_code) as status_codes
    values(method) as methods
    values(user_agent) as user_agents
    min(denied_time) as first_denied
    max(denied_time) as last_denied
    min(success_time) as first_success
    max(success_time) as last_success

| convert
    ctime(first_denied)
    ctime(last_denied)
    ctime(first_success)
    ctime(last_success)

| eval interpretation=case(
    denied_requests>0 AND successful_2xx>0,
        "Denied attempts followed by successful endpoint responses",

    denied_requests>0 AND successful_2xx=0,
        "Attempts observed but no successful endpoint response",

    true(),
        "No clear denied-to-success transition"
)
