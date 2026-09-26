index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| eval source_ip=src_ip

| where
    (
        sourcetype="bytebrew:loyalty_audit"
        AND customer_username="jordan.lee"
        AND export_id="EXP-JL-0406"
    )
    OR
    (
        sourcetype="bytebrew:auth_audit"
        AND source_ip="10.20.20.21"
    )

| eval export_event=if(
    sourcetype="bytebrew:loyalty_audit"
    AND (
        action="export_prepare"
        OR action="export_complete"
    ),
    1,
    0
)

| eval completed_export=if(
    sourcetype="bytebrew:loyalty_audit"
    AND action="export_complete"
    AND result="success",
    1,
    0
)

| eval jordan_auth=if(
    sourcetype="bytebrew:auth_audit"
    AND username="jordan.lee",
    1,
    0
)

| eval auth_success=if(
    sourcetype="bytebrew:auth_audit"
    AND result="success",
    1,
    0
)

| eval auth_failure=if(
    sourcetype="bytebrew:auth_audit"
    AND result="failure",
    1,
    0
)

| eval loyalty_account=if(
    sourcetype="bytebrew:loyalty_audit",
    customer_username,
    null()
)

| eval exported_scope=if(
    sourcetype="bytebrew:loyalty_audit",
    data_scope,
    null()
)

| eval export_identifier=if(
    sourcetype="bytebrew:loyalty_audit",
    export_id,
    null()
)

| eval export_ip=if(
    sourcetype="bytebrew:loyalty_audit",
    source_ip,
    null()
)

| eval loyalty_action=if(
    sourcetype="bytebrew:loyalty_audit",
    action,
    null()
)

| eval loyalty_result=if(
    sourcetype="bytebrew:loyalty_audit",
    result,
    null()
)

| eval loyalty_note=if(
    sourcetype="bytebrew:loyalty_audit",
    notes,
    null()
)

| eval export_debug=if(
    sourcetype="bytebrew:loyalty_audit",
    debug_blob,
    null()
)

| eval auth_user=if(
    sourcetype="bytebrew:auth_audit",
    username,
    null()
)

| eval auth_action=if(
    sourcetype="bytebrew:auth_audit",
    action,
    null()
)

| eval export_time=if(
    export_event=1,
    _time,
    null()
)

| stats
    values(loyalty_account) as loyalty_account
    sum(export_event) as export_events
    sum(completed_export) as successful_export_completions
    values(exported_scope) as exported_data_scope
    values(export_identifier) as export_id
    values(export_ip) as export_source_ip
    values(loyalty_action) as loyalty_actions
    values(loyalty_result) as export_results
    values(loyalty_note) as loyalty_notes
    values(export_debug) as debug_blob
    sum(jordan_auth) as matching_jordan_auth_events
    values(auth_user) as auth_users_on_export_ip
    values(auth_action) as auth_actions_on_export_ip
    sum(auth_success) as auth_successes_on_export_ip
    sum(auth_failure) as auth_failures_on_export_ip
    earliest(export_time) as first_export
    latest(export_time) as last_export

| convert
    ctime(first_export)
    ctime(last_export)

| eval evidence_conclusion=case(

    successful_export_completions>0
    AND matching_jordan_auth_events=0,
        "Successful Jordan Lee export confirmed; no matching Jordan Lee authentication found on export IP",

    successful_export_completions>0
    AND matching_jordan_auth_events>0,
        "Successful Jordan Lee export and matching authentication confirmed",

    true(),
        "Export evidence incomplete"
)
