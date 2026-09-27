<form version="1.1">

  <label>ByteBrew Café Co. Security Dashboard</label>

  <fieldset submitButton="false">
    <input type="time" token="global_time">
      <label>Time Range</label>
      <default>
        <earliest>0</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>


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
        <option name="underLabel">Failed alignment</option>

      </single>
    </panel>


    <panel>
      <single>
        <title>Successful Loyalty Exports</title>

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
        <option name="underLabel">Completed exports</option>

      </single>
    </panel>

  </row>


  <row>

    <panel>
      <table>
        <title>Top Sources of Unauthorised Access</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search status_code=401 OR status_code=403

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
        <title>Unauthorised Requests by Location</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"
| search status_code=401 OR status_code=403

| iplocation id.orig_h

| eval Country=coalesce(
    Country,
    if(
        cidrmatch("10.0.0.0/8",id.orig_h),
        "Private/Internal",
        "Unmapped"
    )
)

| stats count as unauthorized_requests by Country

| sort - unauthorized_requests

| head 10

| rename
    Country as "Location"
    unauthorized_requests as "Unauthorised Requests"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">bar</option>
        <option name="charting.legend.placement">none</option>

      </chart>
    </panel>

  </row>


  <row>

    <panel>
      <chart>
        <title>Ordering Platform Availability</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"

| where
    host="order.bytebrew.example"
    OR like(uri,"/api/order/%")

| timechart span=5m
    count(eval(status_code>=200 AND status_code<300)) as "Successful 2xx"
    count(eval(status_code>=500)) as "Server Errors 5xx"
    count(eval(status_code=503)) as "HTTP 503"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">bottom</option>

      </chart>
    </panel>


    <panel>
      <chart>
        <title>POS Workstation Network Traffic</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:network_conn"
| search id.orig_h="192.168.50.18"

| eval network_bytes=
    coalesce(orig_bytes,0)
    +
    coalesce(resp_bytes,0)

| eval network_MB=
    network_bytes/1024/1024

| timechart span=5m
    sum(network_MB) as "Network Traffic MB"
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="charting.chart">line</option>
        <option name="charting.legend.placement">none</option>

      </chart>
    </panel>

  </row>


  <row>

    <panel>
      <table>
        <title>POS Workstation Top Destinations</title>

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


    <panel>
      <table>
        <title>Email Alignment Failures</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:mail_audit"
| search auth_result="fail_alignment"

| eval Time=strftime(
    _time,
    "%Y-%m-%d %H:%M:%S"
)

| table
    Time
    display_from
    subject
    auth_result
    src_ip
    dest_ip

| rename
    display_from as "Displayed Sender"
    subject as "Subject"
    auth_result as "Authentication"
    src_ip as "Source IP"
    dest_ip as "Destination IP"

| sort - Time
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">13</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>

  </row>


  <row>

    <panel>
      <table>
        <title>Suspicious External File Transfer</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:file_share_audit"
| search dest_domain="suspicious-transfer.example"

| eval Time=strftime(
    _time,
    "%Y-%m-%d %H:%M:%S"
)

| table
    Time
    username
    action
    filename
    dest_domain
    share_id
    link_label
    notes

| rename
    username as "User"
    action as "Action"
    filename as "File"
    dest_domain as "Destination"
    share_id as "Share ID"
    link_label as "Link"
    notes as "Notes"

| sort Time
          ]]></query>

          <earliest>$global_time.earliest$</earliest>
          <latest>$global_time.latest$</latest>
        </search>

        <option name="count">20</option>
        <option name="drilldown">none</option>
        <option name="wrap">true</option>

      </table>
    </panel>


    <panel>
      <table>
        <title>Loyalty Account Export Activity</title>

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
    values(data_scope) as data_scope
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
    customer_username as "Account"
    export_events as "Export Events"
    successful_exports as "Successful Exports"
    data_scope as "Data Scope"
    export_ids as "Export ID"
    source_ips as "Source IP"
    notes as "Notes"
    first_seen as "First Seen"
    last_seen as "Last Seen"
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


  <row>

    <panel>
      <table>
        <title>Jordan Lee Export and Authentication Activity</title>

        <search>
          <query><![CDATA[
index="bytebrew"
(
    sourcetype="bytebrew:loyalty_audit"
    OR sourcetype="bytebrew:auth_audit"
)

| eval account=coalesce(
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
    by sourcetype account source_ip

| rename
    sourcetype as "Source"
    account as "Account"
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


    <panel>
      <table>
        <title>System Changes</title>

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

  </row>


  <row>

    <panel>
      <chart>
        <title>Web Activity Trend</title>

        <search>
          <query><![CDATA[
index="bytebrew"
| search sourcetype="bytebrew:web_access"

| timechart span=1h
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
