<form version="1.1">
  <label>ByteBrew Café Co. - SOC Security Monitoring Dashboard</label>
  <description>
    Security monitoring dashboard for ByteBrew Café Co. covering unauthorised access,
    geographic anomalies, web availability, POS performance, suspicious email activity,
    external file sharing, and loyalty-account exports.
  </description>

  <fieldset submitButton="false">
    <input type="time" token="global_time">
      <label>Monitoring Period</label>
      <default>
        <earliest>0</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>


  <!-- ====================================================== -->
  <!-- ROW 1 - SECURITY OVERVIEW KPIs                         -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <single>
        <title>Unauthorised Web Requests</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| stats count(eval(status_code=401 OR status_code=403)) as unauthorized_requests
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="drilldown">none</option>
        <option name="numberPrecision">0</option>
        <option name="underLabel">HTTP 401 / 403</option>

      </single>
    </panel>


    <panel>
      <single>
        <title>Web Server Errors</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| stats count(eval(status_code>=500)) as server_errors
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="drilldown">none</option>
        <option name="numberPrecision">0</option>
        <option name="underLabel">HTTP 5xx</option>

      </single>
    </panel>


    <panel>
      <single>
        <title>Email Alignment Failures</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| stats count(eval(auth_result="fail_alignment")) as alignment_failures
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="drilldown">none</option>
        <option name="numberPrecision">0</option>
        <option name="underLabel">Potential spoofing</option>

      </single>
    </panel>


    <panel>
      <single>
        <title>Loyalty Export Completions</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:loyalty_audit"
| stats count(eval(action="export_complete" AND result="success")) as successful_exports
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="drilldown">none</option>
        <option name="numberPrecision">0</option>
        <option name="underLabel">Successful exports</option>

      </single>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 2 - UNAUTHORISED ACCESS                           -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <table>

        <title>Top 10 Sources of Unauthorised Access Attempts</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| eval unauthorized=if(status_code=401 OR status_code=403,1,0)
| where unauthorized=1
| stats
    count as unauthorized_attempts
    dc(uri) as unique_targets
    values(method) as methods
    by id.orig_h
| sort - unauthorized_attempts
| head 10
| rename
    id.orig_h as "Source IP"
    unauthorized_attempts as "Unauthorised Attempts"
    unique_targets as "Unique Targets"
    methods as "Methods"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">10</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <chart>

        <title>Unauthorised Requests by Geographic Region</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search status_code=401 OR status_code=403
| iplocation id.orig_h
| eval Country=coalesce(
    Country,
    if(cidrmatch("10.0.0.0/8",id.orig_h),"Private/Internal","Unmapped")
)
| stats count as unauthorized_requests by Country
| sort - unauthorized_requests
| head 10
| rename
    Country as "Region"
    unauthorized_requests as "Unauthorised Requests"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">bar</option>
        <option name="charting.legend.placement">none</option>
        <option name="charting.axisTitleX.text">Unauthorised Requests</option>
        <option name="charting.axisTitleY.text">Region</option>

      </chart>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 3 - WEB PLATFORM SECURITY & AVAILABILITY           -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <chart>

        <title>Ordering Platform - Successful vs Server Error Responses</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search host="order.bytebrew.example"
| timechart span=5m
    count(eval(status_code>=200 AND status_code<300)) as "Successful 2xx"
    count(eval(status_code>=500)) as "Server Errors 5xx"
    count(eval(status_code=503)) as "Service Unavailable 503"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleY.text">Requests per 5 Minutes</option>

      </chart>
    </panel>


    <panel>
      <table>

        <title>High-Risk Web Endpoint Activity</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"

| eval sensitive=if(
    match(
        lower(uri),
        "/api/private|/api/debug|/internal|/admin|/config|\.env|\.git|backup|server-status"
    ),
    1,
    0
)

| where sensitive=1

| stats
    count as requests
    count(eval(status_code=401 OR status_code=403)) as denied
    count(eval(status_code>=200 AND status_code<300)) as responses_2xx
    count(eval(status_code>=500)) as server_errors
    values(status_code) as status_codes
    values(method) as methods
    by id.orig_h uri

| sort - requests
| head 15

| rename
    id.orig_h as "Source IP"
    uri as "Endpoint"
    requests as "Requests"
    denied as "Denied"
    responses_2xx as "2xx Responses"
    server_errors as "5xx Errors"
    status_codes as "Status Codes"
    methods as "Methods"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">15</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 4 - POS PERFORMANCE                               -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <chart>

        <title>POS Workstation 192.168.50.18 - Network Load</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:network_conn"
| search id.orig_h="192.168.50.18"

| eval network_bytes=
    coalesce(orig_bytes,0)
    +
    coalesce(resp_bytes,0)

| timechart span=5m
    count as "Connections"
    sum(network_bytes) as "Network Bytes"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>

      </chart>
    </panel>


    <panel>
      <table>

        <title>POS Workstation - Top Network Destinations</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:network_conn"
| search id.orig_h="192.168.50.18"

| eval total_bytes=
    coalesce(orig_bytes,0)
    +
    coalesce(resp_bytes,0)

| stats
    count as connections
    sum(total_bytes) as total_bytes
    values(proto) as protocols
    values(service) as services
    by id.resp_h

| eval traffic_MB=round(
    total_bytes/1024/1024,
    2
)

| sort - total_bytes
| head 10

| rename
    id.resp_h as "Destination IP"
    connections as "Connections"
    traffic_MB as "Traffic MB"
    protocols as "Protocols"
    services as "Services"

| fields
    "Destination IP"
    "Connections"
    "Traffic MB"
    "Protocols"
    "Services"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">10</option>
        <option name="drilldown">none</option>

      </table>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 5 - EMAIL SECURITY                                -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <table>

        <title>Suspicious Email Authentication / Alignment Failures</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| search auth_result="fail_alignment"

| table
    _time
    display_from
    subject
    auth_result
    src_ip
    dest_ip

| rename
    _time as "Time"
    display_from as "Displayed Sender"
    subject as "Subject"
    auth_result as "Authentication"
    src_ip as "Source IP"
    dest_ip as "Destination IP"

| sort - "Time"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">15</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <chart>

        <title>Email Alignment Failures Over Time</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| search auth_result="fail_alignment"
| timechart span=1h count as "Alignment Failures"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">column</option>
        <option name="charting.legend.placement">none</option>

      </chart>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 6 - FILE SHARING / EXFILTRATION                   -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <table>

        <title>External File Sharing Activity</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"

| where isnotnull(dest_domain)

| eval destination_type=if(
    match(
        lower(dest_domain),
        "bytebrew\.example$"
    ),
    "Internal",
    "External"
)

| where destination_type="External"

| table
    _time
    username
    action
    filename
    dest_domain
    share_id
    link_label
    notes

| rename
    _time as "Time"
    username as "User"
    action as "Action"
    filename as "File"
    dest_domain as "External Destination"
    share_id as "Share ID"
    link_label as "Link Label"
    notes as "Notes"

| sort - "Time"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">15</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <table>

        <title>High-Risk External Transfer Activity</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search dest_domain="suspicious-transfer.example"

| table
    _time
    username
    action
    filename
    dest_domain
    share_id
    link_label
    notes

| rename
    _time as "Time"
    username as "User"
    action as "Action"
    filename as "File"
    dest_domain as "Destination"
    share_id as "Share ID"
    link_label as "Link Label"
    notes as "Evidence"

| sort - "Time"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">20</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 7 - LOYALTY ACCOUNT SECURITY                      -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <table>

        <title>Loyalty Account Data Export Activity</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:loyalty_audit"

| where
    action="export_prepare"
    OR action="export_complete"

| stats
    count as export_events
    count(eval(action="export_complete" AND result="success")) as successful_exports
    values(data_scope) as exported_data
    values(export_id) as export_ids
    values(src_ip) as source_ips
    values(notes) as notes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by customer_username

| convert
    ctime(first_seen)
    ctime(last_seen)

| sort - successful_exports

| rename
    customer_username as "Loyalty Account"
    export_events as "Export Events"
    successful_exports as "Successful Exports"
    exported_data as "Data Scope"
    export_ids as "Export ID"
    source_ips as "Source IP"
    notes as "Notes"
    first_seen as "First Seen"
    last_seen as "Last Seen"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">15</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <table>

        <title>Jordan Lee Export / Authentication Source Correlation</title>

        <search>
          <query><![CDATA[
index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| eval identity=coalesce(
    customer_username,
    username
)

| eval source_ip=coalesce(
    src_ip,
    source_ip
)

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

| stats
    count as events
    values(action) as actions
    values(result) as results
    values(data_scope) as data_scope
    values(export_id) as export_ids
    values(notes) as notes
    by sourcetype identity source_ip

| rename
    sourcetype as "Evidence Source"
    identity as "Account"
    source_ip as "Source IP"
    events as "Events"
    actions as "Actions"
    results as "Results"
    data_scope as "Data Scope"
    export_ids as "Export ID"
    notes as "Notes"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">10</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>

  </row>


  <!-- ====================================================== -->
  <!-- ROW 8 - CHANGE / AVAILABILITY MONITORING              -->
  <!-- ====================================================== -->

  <row>

    <panel>
      <table>

        <title>System Change and Maintenance Monitoring</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:system_change"

| where isnotnull(change_id)

| stats
    count as events
    values(action) as actions
    values(status) as statuses
    values(component) as components
    values(actor_display_name) as actors
    values(notes) as notes
    earliest(_time) as start_time
    latest(_time) as end_time
    by change_id

| convert
    ctime(start_time)
    ctime(end_time)

| sort - start_time

| rename
    change_id as "Change ID"
    events as "Events"
    actions as "Actions"
    statuses as "Status"
    components as "Components"
    actors as "Actors"
    notes as "Notes"
    start_time as "Start"
    end_time as "End"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">10</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <chart>

        <title>ByteBrew Web Error Trend</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"

| timechart span=15m
    count(eval(status_code>=200 AND status_code<300)) as "2xx Success"
    count(eval(status_code=401 OR status_code=403)) as "401/403 Denied"
    count(eval(status_code>=500)) as "5xx Errors"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>

      </chart>
    </panel>

  </row>

</form>
