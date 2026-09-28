Incident 1
index="bytebrew"
sourcetype="bytebrew:web_access" uri="/product/*"
| where status_code=200
| eval menu_item=replace(uri,"^/product/","")
| eval menu_item=replace(menu_item,"-","")
| stats count as product_views dc(id.orig_h) as unique_source_ips by menu_item
| sort - product_views
Incident 2
index="bytebrew" sourcetype="bytebrew:web_access"
| iplocation id.orig_h
| eval Country=coalesce(Country,"Unmapped/Private")
| stats count as requests dc(id.orig_h) as unique_ips
    count(eval(status_code=401 OR status_code=403)) as unauthorized
    count(eval(status_code>=400)) as http_errors
    by Country
| eval unauthorized_pct=round((unauthorized/requests)*100,2)
| eval error_pct=round((http_errors/requests)*100,2)
| sort - requests
Incident 3
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search status_code=401 OR status_code=403
| stats count as attempts by id.orig_h uri
| eventstats sum(attempts) as unauthorized_attempts
    dc(uri) as unique_targets by id.orig_h
| sort 0 id.orig_h - attempts
| streamstats count as target_rank by id.orig_h
| where target_rank<=3
| stats first(unauthorized_attempts) as unauthorized_attempts
    first(unique_targets) as unique_targets
    values(uri) as top_targeted_resources
    values(attempts) as target_attempts by id.orig_h
| sort - unauthorized_attempts
| head 10
Incident 4
index="bytebrew" sourcetype="bytebrew:network_conn"
| eval source_ip=coalesce(src_ip,id.orig_h)
| eval destination=coalesce(dest_ip,id.resp_h)
| eval network_bytes=coalesce(bytes,orig_bytes,0)
| eval protocol=coalesce(protocol,proto)
| where source_ip="192.168.50.18"
| bin _time span=5m
| stats count as network_connections
    sum(network_bytes) as network_bytes
    dc(destination) as unique_destinations
    values(destination) as destinations
    values(protocol) as protocols
    by _time
| eventstats avg(network_connections) as avg_connections
    avg(network_bytes) as avg_network_bytes
| eval network_MB=round(network_bytes/1024/1024,2)
| eval avg_network_MB=round(avg_network_bytes/1024/1024,2)
| eval connection_ratio=round(network_connections/avg_connections,1)
| eval traffic_ratio=round(network_MB/avg_network_MB,1)
| sort - network_MB
| head 15
Incident 5
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search id.orig_h="198.51.100.220" uri="/api/private/export"
| eval denied_time=if(status_code=401 OR status_code=403,_time,null())
| eval success_time=if(status_code>=200 AND status_code<300,_time,null())
| stats
    count as total_events
    count(eval(status_code=401 OR status_code=403)) as denied_requests
    count(eval(status_code>=200 AND status_code<300)) as success_2xx
    count(eval(status_code>=500 AND status_code<600)) as server_errors
    min(denied_time) as first_denied
    max(denied_time) as last_denied
    min(success_time) as first_success
    max(success_time) as last_success
    values(status_code) as status_codes
    values(method) as methods
    values(user_agent) as user_agents
| convert ctime(first_denied) ctime(last_denied) ctime(first_success) ctime(last_success)
Incident 6
index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| search auth_result="fail_alignment"
| eval recipient=coalesce(recipient,to,dest_user,rcpt_to)
| eval source_ip=coalesce(src_ip,source_ip,client_ip)
| table _time display_from from recipient subject auth_result source_ip dest_ip
| sort _time
Incident 7
index="bytebrew"
(
    sourcetype="bytebrew:web_access"
    OR sourcetype="bytebrew:system_change"
)
| where _time>=strptime("2026-04-06 10:15:00","%Y-%m-%d %H:%M:%S")
    AND _time<=strptime("2026-04-06 10:40:00","%Y-%m-%d %H:%M:%S")
| eval relevant_web=if(sourcetype="bytebrew:web_access",1,0)
| eval relevant_change=if(sourcetype="bytebrew:system_change",1,0)
| bin _time span=5m
| stats
    count(eval(relevant_web=1)) as requests
    count(eval(relevant_web=1 AND status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(relevant_web=1 AND status_code>=500)) as responses_5xx
    count(eval(relevant_web=1 AND status_code=503)) as responses_503
    values(eval(if(relevant_change=1,_raw,null()))) as system_changes
    by _time
| eval error_pct=if(requests>0,round((responses_5xx/requests)*100,1),null())
| eval success_pct=if(requests>0,round((responses_2xx/requests)*100,1),null())
| sort _time
Incident 8
index="bytebrew"
| search sourcetype="bytebrew:system_change"
| eval note=lower(coalesce(notes,""))
| eval act=lower(coalesce(action,""))
| where
    isnotnull(change_id)
    OR match(note,"maintenance|planned|scheduled maintenance")
    OR match(act,"patch|upgrade|deploy|maintenance")
| where NOT (
    note="background_normal"
    OR note="routine_operational_event"
    OR note="routine_backup_cycle"
)
| stats
    count as events
    earliest(_time) as start_time
    latest(_time) as end_time
    values(action) as actions
    values(status) as statuses
    values(component) as components
    values(actor_display_name) as actors
    values(notes) as notes
    by change_id
| convert ctime(start_time) ctime(end_time)
| sort start_time
Incident 9
index="bytebrew" sourcetype="bytebrew:file_share_audit"
| search dest_domain="suspicious-transfer.example"
| table _time username action filename dest_domain share_id link_label notes
| sort _time
Incident 10
index="bytebrew" sourcetype="bytebrew:loyalty_audit"
("jordan.lee" OR "EXP-JL-0406")
| eval loyalty_account=coalesce(username,user,account)
| eval export_source_ip=coalesce(src_ip,source_ip,client_ip)
| stats
    count as export_events
    count(eval(action="export_complete" AND result="success")) as successful_export_completions
    values(data_scope) as exported_data_scope
    values(export_id) as export_id
    values(export_source_ip) as export_source_ip
    values(action) as loyalty_actions
    values(result) as export_results
    values(notes) as loyalty_notes
    values(debug_blob) as debug_blob
    by loyalty_account
| appendcols [
    search index="bytebrew" sourcetype="bytebrew:auth_audit" "10.20.20.21"
    | eval auth_user=coalesce(username,user,account)
    | stats
        values(auth_user) as auth_users_on_export_ip
        values(action) as auth_actions_on_export_ip
        values(result) as auth_results_on_export_ip
]
