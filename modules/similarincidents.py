from classes import BaseModule, Response, SimilarIncidentsModule, STATError
from shared import rest, data
import json
import datetime as dt

def execute_similarincidents_module(req_body):
    # Initialize the base module and new module
    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])

    similar_incidents = SimilarIncidentsModule()

    # Configuration parameters with defaults
    lookback = req_body.get('LookbackInDays', 90)
    min_similarity_score = req_body.get('MinimumSimilarityScore', 0.7)
    include_false_positives = req_body.get('IncludeFalsePositives', False)
    max_incidents = req_body.get('MaxIncidents', 20)

    # Step 1: Data Gathering - Find similar incidents with KQL
    results = find_similar_incidents(base_object, lookback, min_similarity_score, include_false_positives, max_incidents)
    similar_incidents.DetailedResults = results
    similar_incidents.SimilarIncidentsCount = len(results)
    similar_incidents.SimilarIncidentsFound = bool(results)
    calculate_resolution_stats(similar_incidents)

    # Step 2: Gather current incident context
    current_incident_context = get_current_incident_context(base_object)

    # Step 3: Prepare LLM payload (for output)
    llm_payload = {
        "current_incident": current_incident_context,
        "similar_incidents": results
    }
    similar_incidents.LLMInput = llm_payload  # For downstream use

    # Step 4: Add classic summary comment if configured
    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        comment = build_classic_comment(base_object, similar_incidents, lookback)
        rest.add_incident_comment(base_object, comment)

    # Add incident task if configured
    if req_body.get('AddIncidentTask', False) and similar_incidents.SimilarIncidentsFound and base_object.IncidentAvailable:
        rest.add_incident_task(base_object, 'Review Similar Incidents', req_body.get('IncidentTaskInstructions'))

    return Response(similar_incidents)

def find_similar_incidents(base_object, lookback, min_similarity_score, include_false_positives, max_incidents):
    account_query = build_account_entity_query(base_object)
    ip_query = build_ip_entity_query(base_object)
    host_query = build_host_entity_query(base_object)
    title_query = build_title_similarity_query(base_object)
    tactics_query = build_tactics_similarity_query(base_object)

    query = f'''
    let currentIncidentId = "{base_object.IncidentARMId.split('/')[-1]}";
    let lookback = {lookback}d;
    let minSimilarityScore = {min_similarity_score};
    let similarIncidents = (
        {account_query}
        union
        {ip_query}
        union
        {host_query}
        union
        {title_query}
        union
        {tactics_query}
    )
    | summarize
        SimilarityScore = max(SimilarityScore),
        MatchReason = make_set(MatchReason),
        MatchedEntities = make_set(MatchedEntity)
        by IncidentId, Title, Severity, Status, Classification, CreatedTime, ClosedTime;
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | where {'true' if include_false_positives else 'Classification != "FalsePositive"'}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project
        IncidentId = IncidentNumber,
        Title,
        Description,
        Severity,
        Status,
        Classification,
        CreatedTime,
        ClosedTime,
        Owner = tostring(Owner),
        Labels,
        IncidentUrl,
        TacticsRaw = split(Tactics, ","),
        Resolution = tostring(Resolution),
        Comments = tostring(Comments)
    | join kind=inner similarIncidents on IncidentId
    | extend
        ResolutionTime = iff(Status == "Closed", datetime_diff('minute', ClosedTime, CreatedTime), 0),
        Tactics = array_sort_asc(TacticsRaw)
    | project-away TacticsRaw
    | sort by SimilarityScore desc
    | take {max_incidents}
    '''

    results = rest.execute_la_query(base_object, query, lookback)
    results = enhance_results_with_links(base_object, results)
    return results

def build_account_entity_query(base_object):
    upn_list = base_object.get_account_upn_list()
    id_list = base_object.get_account_id_list()
    if not upn_list and not id_list:
        return "(SecurityIncident | limit 0)"
    upn_filter = f"UserPrincipalName in~ ({','.join([f'{upn}' for upn in upn_list])})" if upn_list else "false"
    id_filter = f"AccountId in~ ({','.join([f'{id}' for id in id_list])})" if id_list else "false"
    return f'''
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | mvexpand todynamic(Entities)
    | where Entities.Type == "account"
    | extend
        UserPrincipalName = tostring(Entities.properties.userPrincipalName),
        AccountId = tostring(Entities.properties.aadUserId)
    | where {upn_filter} or {id_filter}
    | extend
        MatchReason = "Account Entity",
        MatchedEntity = iff(isnotempty(UserPrincipalName), UserPrincipalName, AccountId),
        SimilarityScore = 0.8
    | project IncidentId = IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime, SimilarityScore, MatchReason, MatchedEntity
    '''

def build_ip_entity_query(base_object):
    ip_list = base_object.get_ip_list()
    if not ip_list:
        return "(SecurityIncident | limit 0)"
    return f'''
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | mvexpand todynamic(Entities)
    | where Entities.Type == "ip"
    | extend IPAddress = tostring(Entities.properties.address)
    | where IPAddress in~ ({','.join([f'{ip}' for ip in ip_list])})
    | extend
        MatchReason = "IP Entity",
        MatchedEntity = IPAddress,
        SimilarityScore = 0.85
    | project IncidentId = IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime, SimilarityScore, MatchReason, MatchedEntity
    '''

def build_host_entity_query(base_object):
    hostname_list = []
    fqdn_list = []
    for host in base_object.Hosts:
        if host.get('Hostname'):
            hostname_list.append(host.get('Hostname'))
        if host.get('FQDN'):
            fqdn_list.append(host.get('FQDN'))
    if not hostname_list and not fqdn_list:
        return "(SecurityIncident | limit 0)"
    hostname_filter = f"HostName in~ ({','.join([f'{hostname}' for hostname in hostname_list])})" if hostname_list else "false"
    fqdn_filter = f"FQDN in~ ({','.join([f'{fqdn}' for fqdn in fqdn_list])})" if fqdn_list else "false"
    return f'''
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | mvexpand todynamic(Entities)
    | where Entities.Type == "host"
    | extend
        HostName = tostring(Entities.properties.hostName),
        FQDN = tostring(Entities.properties.dnsDomain)
    | extend FQDN = iff(isnotempty(HostName) and isnotempty(FQDN), strcat(HostName, '.', FQDN), FQDN)
    | where {hostname_filter} or {fqdn_filter}
    | extend
        MatchReason = "Host Entity",
        MatchedEntity = iff(isnotempty(HostName), HostName, FQDN),
        SimilarityScore = 0.85
    | project IncidentId = IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime, SimilarityScore, MatchReason, MatchedEntity
    '''

def build_title_similarity_query(base_object):
    title = ""
    if base_object.Alerts and len(base_object.Alerts) > 0:
        title = base_object.Alerts[0].get('properties', {}).get('alertDisplayName', '')
    if not title:
        return "(SecurityIncident | limit 0)"
    generalized_title = clean_title_for_matching(title)
    return f'''
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | extend CleanedTitle = clean_title_for_matching(Title)
    | extend TitleSimilarity = string_distance(CleanedTitle, "{generalized_title}", "JaroWinkler")
    | where TitleSimilarity > minSimilarityScore
    | extend
        MatchReason = "Similar Title",
        MatchedEntity = Title,
        SimilarityScore = TitleSimilarity
    | project IncidentId = IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime, SimilarityScore, MatchReason, MatchedEntity
    '''

def build_tactics_similarity_query(base_object):
    tactics = base_object.get_alert_tactics()
    if not tactics:
        return "(SecurityIncident | limit 0)"
    return f'''
    SecurityIncident
    | where TimeGenerated > ago(lookback)
    | where IncidentNumber != currentIncidentId
    | extend TacticsList = split(Tactics, ",")
    | mv-expand TacticsList
    | where TacticsList in~ ({','.join([f'{tactic}' for tactic in tactics])})
    | summarize
        MatchingTactics = make_set(TacticsList),
        TacticCount = dcount(TacticsList),
        TotalTactics = dcount(split(Tactics, ","))
        by IncidentId = IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime
    | extend
        MatchReason = "Similar Tactics",
        MatchedEntity = strcat(array_join(MatchingTactics, ", "), " (", TacticCount, "/", TotalTactics, " tactics)"),
        SimilarityScore = 0.4 + ((TacticCount * 1.0) / max(TotalTactics, {len(tactics)})) * 0.6
    | where SimilarityScore > minSimilarityScore
    | project IncidentId, Title, Severity, Status, Classification, CreatedTime, ClosedTime, SimilarityScore, MatchReason, MatchedEntity
    '''

def get_current_incident_context(base_object):
    """Gather context for the current incident for the LLM"""
    context = {
        "IncidentId": base_object.IncidentARMId.split('/')[-1] if base_object.IncidentARMId else None,
        "Title": base_object.Alerts[0].get('properties', {}).get('alertDisplayName', '') if base_object.Alerts else '',
        "Description": base_object.Alerts[0].get('properties', {}).get('description', '') if base_object.Alerts else '',
        "Entities": {
            "Accounts": base_object.Accounts,
            "IPs": base_object.IPs,
            "Hosts": base_object.Hosts,
            "URLs": base_object.URLs,
            "Files": base_object.Files,
            "Domains": base_object.Domains
        },
        "Tactics": base_object.get_alert_tactics(),
        "Classification": None,
        "Status": None,
        "Comments": base_object.Comments if hasattr(base_object, 'Comments') else '',
        "Alerts": base_object.Alerts
    }
    return context

def calculate_resolution_stats(similar_incidents):
    results = similar_incidents.DetailedResults
    true_positives = [r for r in results if r.get('Classification') == 'TruePositive']
    false_positives = [r for r in results if r.get('Classification') == 'FalsePositive']
    benign_positives = [r for r in results if r.get('Classification') == 'BenignPositive']
    unresolved = [r for r in results if r.get('Classification') is None or r.get('Classification') == 'Unclassified']
    similar_incidents.TruePositiveCount = len(true_positives)
    similar_incidents.FalsePositiveCount = len(false_positives)
    similar_incidents.BenignPositiveCount = len(benign_positives)
    similar_incidents.UnresolvedCount = len(unresolved)
    similar_incidents.HighestSimilarityScore = max([r.get('SimilarityScore', 0) for r in results]) if results else 0
    closed_incidents = [r for r in results if r.get('Status') == 'Closed' and r.get('ResolutionTime')]
    total_time = sum([r.get('ResolutionTime', 0) for r in closed_incidents])
    similar_incidents.AverageResolutionTime = total_time / len(closed_incidents) if closed_incidents else 0
    all_tactics = []
    for incident in results:
        tactics = incident.get('Tactics', [])
        if tactics:
            all_tactics.extend(tactics)
    tactic_counts = {}
    for tactic in all_tactics:
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
    similar_incidents.MostCommonTactics = [t[0] for t in sorted_tactics[:5]] if sorted_tactics else []
    title_groups = {}
    for incident in results:
        title = incident.get('Title', '')
        if title:
            if title not in title_groups:
                title_groups[title] = []
            title_groups[title].append(incident.get('IncidentId'))
    title_counts = {title: len(incidents) for title, incidents in title_groups.items()}
    similar_incidents.MostCommonTitle = max(title_counts.items(), key=lambda x: x[1])[0] if title_counts else ""

def build_classic_comment(base_object, similar_incidents, lookback):
    linked_results = similar_incidents.DetailedResults
    main_table = data.list_to_html_table(linked_results, escape_html=False)
    stats_html = f"""
    <h4>Resolution Statistics</h4>
    <ul>
        <li>True Positives: {similar_incidents.TruePositiveCount}</li>
        <li>False Positives: {similar_incidents.FalsePositiveCount}</li>
        <li>Benign Positives: {similar_incidents.BenignPositiveCount}</li>
        <li>Unresolved: {similar_incidents.UnresolvedCount}</li>
        <li>Average Resolution Time: {format_duration(similar_incidents.AverageResolutionTime)}</li>
    </ul>
    """
    patterns_html = ""
    if similar_incidents.MostCommonTactics:
        patterns_html += f"<h4>Common Patterns</h4><ul>"
        patterns_html += f"<li>Most Common Tactics: {', '.join(similar_incidents.MostCommonTactics)}</li>"
        if similar_incidents.MostCommonTitle:
            patterns_html += f"<li>Most Common Title: {similar_incidents.MostCommonTitle}</li>"
        patterns_html += "</ul>"
    comment = f"""<h3>Similar Incidents Analysis (Last {lookback} days)</h3>
    A total of {similar_incidents.SimilarIncidentsCount} similar incidents were found.<br />
    {stats_html}
    {patterns_html}
    <h4>Similar Incidents List</h4>
    {main_table}
    """
    return comment

def enhance_results_with_links(base_object, results):
    enhanced_results = []
    for result in results:
        incident_id = result.get('IncidentId')
        incident_url = result.get('IncidentUrl', '')
        if incident_id and incident_url:
            result['IncidentId'] = f'<a href="{incident_url}" target="_blank">{incident_id}</a>'
        for time_field in ['CreatedTime', 'ClosedTime']:
            if result.get(time_field):
                result[time_field] = format_timestamp(result[time_field])
        for array_field in ['MatchReason', 'MatchedEntities', 'Tactics']:
            if result.get(array_field) and isinstance(result[array_field], list):
                result[array_field] = ', '.join(result[array_field])
        if 'SimilarityScore' in result:
            try:
                result['SimilarityScore'] = f"{float(result['SimilarityScore']) * 100:.1f}%"
            except Exception:
                pass
        enhanced_results.append(result)
    return enhanced_results

def clean_title_for_matching(title):
    import re
    title = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '', title)
    title = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', '', title)
    title = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '', title)
    title = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '', title)
    title = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '', title)
    title = re.sub(r'\s+', ' ', title).strip()
    return title

def format_timestamp(timestamp):
    if isinstance(timestamp, str):
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return timestamp
    return timestamp

def format_duration(minutes):
    if minutes < 60:
        return f"{minutes:.0f} minutes"
    elif minutes < 1440:
        hours = minutes / 60
        return f"{hours:.1f} hours"
    else:
        days = minutes / 1440
        return f"{days:.1f} days"