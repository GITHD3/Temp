F

index="bytebrew" sourcetype="bytebrew:network_conn" "192.168.50.18"
| eval destination=coalesce(dest_ip,id.resp_h,dst_ip)
| eval network_bytes=coalesce(bytes,orig_bytes,resp_bytes,0)
| eval protocol=coalesce(protocol,proto)
| bin _time span=5m
| stats
    count as network_connections
    sum(network_bytes) as network_bytes
    dc(destination) as unique_destinations
    values(destination) as destinations
    values(protocol) as protocols
    by _time
| eventstats
    avg(network_connections) as avg_connections
    avg(network_bytes) as avg_network_bytes
| eval network_MB=round(network_bytes/1024/1024,2)
| eval avg_network_MB=round(avg_network_bytes/1024/1024,2)
| eval connection_ratio=round(network_connections/avg_connections,1)
| eval traffic_ratio=round(network_bytes/avg_network_bytes,1)
| sort - network_bytes
| head 15


index="bytebrew" sourcetype="bytebrew:loyalty_audit"
("jordan.lee" OR "EXP-JL-0406")
| stats
    count as export_events
    count(eval(action="export_complete" AND result="success")) as successful_export_completions
    values(data_scope) as exported_data_scope
    values(export_id) as export_id
    values(src_ip) as export_source_ip
    values(action) as loyalty_actions
    values(result) as export_results
    values(notes) as loyalty_notes
    values(debug_blob) as debug_blob
| eval loyalty_account="jordan.lee"
| appendcols [
    search index="bytebrew" sourcetype="bytebrew:auth_audit" "10.20.20.21"
    | stats
        values(username) as auth_users_on_export_ip
        values(action) as auth_actions_on_export_ip
        values(result) as auth_results_on_export_ip
]
| table
    loyalty_account
    export_events
    successful_export_completions
    exported_data_scope
    export_id
    export_source_ip
    loyalty_actions
    export_results
    loyalty_notes
    debug_blob
    auth_users_on_export_ip
    auth_actions_on_export_ip
    auth_results_on_export_ip
