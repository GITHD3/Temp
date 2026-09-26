index="bytebrew"
(
    sourcetype="bytebrew:web_access"
    OR sourcetype="bytebrew:system_change"
)

| eval evidence_type=case(
    sourcetype="bytebrew:web_access","Web",
    sourcetype="bytebrew:system_change","System Change",
    true(),"Other"
)

| eval relevant_web=if(
    sourcetype="bytebrew:web_access"
    AND host="order.bytebrew.example",
    1,
    0
)

| eval change_text=if(
    sourcetype="bytebrew:system_change",
    _raw,
    null()
)

| where
    (
        relevant_web=1
        AND _time>=strptime(
            "2026-04-06 10:15:00",
            "%Y-%m-%d %H:%M:%S"
        )
        AND _time<=strptime(
            "2026-04-06 11:00:00",
            "%Y-%m-%d %H:%M:%S"
        )
    )
    OR
    (
        sourcetype="bytebrew:system_change"
        AND _time>=strptime(
            "2026-04-06 10:15:00",
            "%Y-%m-%d %H:%M:%S"
        )
        AND _time<=strptime(
            "2026-04-06 11:00:00",
            "%Y-%m-%d %H:%M:%S"
        )
    )

| bin _time span=5m

| stats
    count(eval(relevant_web=1)) as requests
    count(eval(relevant_web=1 AND status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(relevant_web=1 AND status_code>=500)) as responses_5xx
    count(eval(relevant_web=1 AND status_code=503)) as responses_503
    values(change_text) as system_changes
    by _time

| eval error_pct=if(
    requests>0,
    round((responses_5xx/requests)*100,1),
    null()
)

| eval success_pct=if(
    requests>0,
    round((responses_2xx/requests)*100,1),
    null()
)

| sort _time
