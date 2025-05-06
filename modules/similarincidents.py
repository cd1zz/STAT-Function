from classes import BaseModule, Response, SimilarIncidentsModule, STATError
from shared import rest, data
import json
from datetime import datetime, timedelta
import statistics

def execute_similarincidents_module(req_body):
    """
    Execute the Similar Incidents module to find and analyze related past incidents.
    
    This module identifies similar incidents by comparing entities, titles, and tactics,
    then analyzes their resolution status and provides statistics for patterns.
    """
    # Initialize the base module and load input data
    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    
    # Initialize the SimilarIncidents module
    similar_incidents = SimilarIncidentsModule()
    
    # Get parameters from request body
    lookback_days = req_body.get('LookbackInDays', 90)
    similarity_threshold = req_body.get('SimilarityThreshold', 0.5)
    max_incidents = req_body.get('MaxIncidents', 50)
    
    # Get match parameters
    match_by_entity = req_body.get('MatchByEntity', True)
    match_by_title = req_body.get('MatchByTitle', True)
    match_by_tactics = req_body.get('MatchByTactics', True)
    
    # Check if we have an incident to compare against
    if not base_object.IncidentAvailable:
        raise STATError('There is no incident associated with this STAT triage. Unable to find similar incidents.')
    
    # Gather data from the current incident
    current_incident = get_current_incident_details(base_object)
    
    # Search for similar incidents
    similar_incidents_data = search_similar_incidents(
        base_object, 
        current_incident, 
        lookback_days, 
        similarity_threshold,
        max_incidents,
        match_by_entity,
        match_by_title,
        match_by_tactics
    )
    
    # Analyze the similar incidents
    analyze_similar_incidents(similar_incidents, similar_incidents_data, current_incident)
    
    # Add comment to the incident if requested
    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        add_incident_comment(base_object, similar_incidents)
    
    # Add task to the incident if requested and if similar incidents were found
    if req_body.get('AddIncidentTask', False) and similar_incidents.SimilarIncidentsFound and base_object.IncidentAvailable:
        task_description = req_body.get('IncidentTaskInstructions', 'Review similar incidents for patterns and resolution approaches')
        task_result = rest.add_incident_task(base_object, 'Review Similar Incidents', task_description)
    
    return Response(similar_incidents)

def get_current_incident_details(base_object):
    """
    Retrieve details about the current incident for comparison.
    """
    path = f'{base_object.IncidentARMId}?api-version=2023-02-01'
    current_incident = json.loads(rest.rest_call_get(base_object, 'arm', path).content)
    
    # Extract entity information
    entity_types = {
        'accounts': [account.get('userPrincipalName', '') for account in base_object.Accounts if account.get('userPrincipalName')],
        'ips': [ip.get('Address', '') for ip in base_object.IPs if ip.get('Address')],
        'hosts': [host.get('FQDN', '') for host in base_object.Hosts if host.get('FQDN')],
        'domains': [domain.get('Domain', '') for domain in base_object.Domains if domain.get('Domain')],
        'filehashes': [hash.get('FileHash', '') for hash in base_object.FileHashes if hash.get('FileHash')]
    }
    
    # Extract tactics from the related analytic rules
    tactics = []
    for alert in base_object.Alerts:
        if 'properties' in alert and 'tactics' in alert['properties']:
            tactics.extend(alert['properties']['tactics'])
    
    # Remove duplicates from tactics
    tactics = list(set(tactics))
    
    return {
        'id': current_incident['id'],
        'title': current_incident['properties'].get('title', ''),
        'description': current_incident['properties'].get('description', ''),
        'severity': current_incident['properties'].get('severity', ''),
        'status': current_incident['properties'].get('status', ''),
        'tactics': tactics,
        'entities': entity_types,
        'createdTime': current_incident['properties'].get('createdTimeUtc', '')
    }

def search_similar_incidents(base_object, current_incident, lookback_days, similarity_threshold, max_incidents, match_by_entity, match_by_title, match_by_tactics):
    """
    Search for incidents similar to the current one.
    
    Similarity is determined by common entities, similar titles, and matching tactics.
    """
    # Calculate the lookback date
    lookback_date = (datetime.now() - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Construct the KQL query to find similar incidents
    query = f"""
    let currentIncidentId = "{current_incident['id']}";
    let lookbackDate = datetime({lookback_date});
    let maxIncidents = {max_incidents};
    """
    
    # Add entity tables to the query if we're matching by entity
    if match_by_entity:
        for entity_type, entities in current_incident['entities'].items():
            if entities:
                entity_str = ", ".join([f"'{entity}'" for entity in entities])
                query += f"""
                let current_{entity_type} = dynamic([{entity_str}]);
                """
    
    # Add title and tactics if we're matching by those
    if match_by_title:
        query += f"""
        let currentTitle = "{current_incident['title'].replace('"', '\\"')}";
        """
    
    if match_by_tactics and current_incident['tactics']:
        tactics_str = ", ".join([f"'{tactic}'" for tactic in current_incident['tactics']])
        query += f"""
        let currentTactics = dynamic([{tactics_str}]);
        """
    
    # Main query part
    query += """
    SecurityIncident
    | where TimeGenerated > lookbackDate
    | where IncidentNumber != 0 // Filter out drafts/tests
    | where IncidentUrl != "" // Ensure valid incidents only
    | extend currentIncidentFragments = split(currentIncidentId, "/")
    | extend currentIncidentFragmentsLength = array_length(currentIncidentFragments)
    | extend currentIncidentShortId = tostring(currentIncidentFragments[currentIncidentFragmentsLength - 1])
    | extend incidentFragments = split(IncidentName, "/")
    | extend incidentFragmentsLength = array_length(incidentFragments)
    | extend incidentShortId = tostring(incidentFragments[incidentFragmentsLength - 1])
    | where incidentShortId != currentIncidentShortId // Exclude current incident
    | summarize arg_max(TimeGenerated, *) by IncidentName // Get latest state for each incident
    """
    
    # Add match calculation based on selected criteria
    match_conditions = []
    
    if match_by_entity:
        # Add entity matching conditions
        entity_conditions = []
        
        # Account matching
        if current_incident['entities']['accounts']:
            entity_conditions.append("""
            | extend AccountEntities = extract_json("$.entities.accounts", tostring(AdditionalData), dynamic([]))
            | extend AccountMatchCount = array_length(set_intersect(AccountEntities, current_accounts))
            | extend TotalCurrentAccounts = array_length(current_accounts)
            | extend AccountMatchScore = iff(TotalCurrentAccounts > 0, 1.0 * AccountMatchCount / TotalCurrentAccounts, 0)
            """)
            match_conditions.append("AccountMatchScore")
        
        # IP matching
        if current_incident['entities']['ips']:
            entity_conditions.append("""
            | extend IPEntities = extract_json("$.entities.ips", tostring(AdditionalData), dynamic([]))
            | extend IPMatchCount = array_length(set_intersect(IPEntities, current_ips))
            | extend TotalCurrentIPs = array_length(current_ips)
            | extend IPMatchScore = iff(TotalCurrentIPs > 0, 1.0 * IPMatchCount / TotalCurrentIPs, 0)
            """)
            match_conditions.append("IPMatchScore")
        
        # Host matching
        if current_incident['entities']['hosts']:
            entity_conditions.append("""
            | extend HostEntities = extract_json("$.entities.hosts", tostring(AdditionalData), dynamic([]))
            | extend HostMatchCount = array_length(set_intersect(HostEntities, current_hosts))
            | extend TotalCurrentHosts = array_length(current_hosts)
            | extend HostMatchScore = iff(TotalCurrentHosts > 0, 1.0 * HostMatchCount / TotalCurrentHosts, 0)
            """)
            match_conditions.append("HostMatchScore")
        
        # Domain matching
        if current_incident['entities']['domains']:
            entity_conditions.append("""
            | extend DomainEntities = extract_json("$.entities.domains", tostring(AdditionalData), dynamic([]))
            | extend DomainMatchCount = array_length(set_intersect(DomainEntities, current_domains))
            | extend TotalCurrentDomains = array_length(current_domains)
            | extend DomainMatchScore = iff(TotalCurrentDomains > 0, 1.0 * DomainMatchCount / TotalCurrentDomains, 0)
            """)
            match_conditions.append("DomainMatchScore")
        
        # FileHash matching
        if current_incident['entities']['filehashes']:
            entity_conditions.append("""
            | extend FileHashEntities = extract_json("$.entities.filehashes", tostring(AdditionalData), dynamic([]))
            | extend FileHashMatchCount = array_length(set_intersect(FileHashEntities, current_filehashes))
            | extend TotalCurrentFileHashes = array_length(current_filehashes)
            | extend FileHashMatchScore = iff(TotalCurrentFileHashes > 0, 1.0 * FileHashMatchCount / TotalCurrentFileHashes, 0)
            """)
            match_conditions.append("FileHashMatchScore")
        
        # Apply all entity conditions
        for condition in entity_conditions:
            query += condition
    
    # Title matching
    if match_by_title:
        query += """
        | extend TitleSimilarity = iff(Title contains currentTitle or currentTitle contains Title, 0.8, 0)
        """
        match_conditions.append("TitleSimilarity")
    
    # Tactics matching
    if match_by_tactics and current_incident['tactics']:
        query += """
        | extend IncidentTactics = todynamic(RelatedAnalyticRuleIds)
        | mv-expand IncidentTactics to typeof(string)
        | extend IncidentTactics = extract("tactics\":([^\\]]*)", 1, tostring(IncidentTactics))
        | extend IncidentTactics = replace_string(IncidentTactics, "\"", "")
        | extend IncidentTactics = split(IncidentTactics, ",")
        | summarize Tactics = any(IncidentTactics) by IncidentName, IncidentNumber, Title, Severity, Status, Classification, ClassificationComment, ClassificationReason, IncidentUrl, CreatedTime, LastModifiedTime, ClosedTime, FirstActivityTime, LastActivityTime, AccountMatchScore, IPMatchScore, HostMatchScore, DomainMatchScore, FileHashMatchScore, TitleSimilarity
        | extend TacticMatchCount = array_length(set_intersect(Tactics, currentTactics))
        | extend TotalCurrentTactics = array_length(currentTactics)
        | extend TacticsMatchScore = iff(TotalCurrentTactics > 0, 1.0 * TacticMatchCount / TotalCurrentTactics, 0)
        """
        match_conditions.append("TacticsMatchScore")
    
    # Calculate overall similarity score
    if match_conditions:
        similarity_expr = " + ".join(match_conditions)
        divisor = len(match_conditions)
        query += f"""
        | extend SimilarityScore = ({similarity_expr}) / {divisor}
        | where SimilarityScore >= {similarity_threshold}
        """
    else:
        # Fallback if no match conditions
        query += """
        | extend SimilarityScore = 0
        """
    
    # Finalize query with sorting and limits
    query += """
    | project IncidentName, 
             IncidentNumber, 
             Title, 
             Severity, 
             Status, 
             Classification,
             ClassificationComment,
             ClassificationReason,
             IncidentUrl,
             Tactics,
             FirstActivityTime,
             LastActivityTime,
             CreatedTime,
             LastModifiedTime,
             ClosedTime,
             ResolutionTime = iff(Status == "Closed", ClosedTime, datetime(null)),
             SimilarityScore
    | order by SimilarityScore desc, CreatedTime desc
    | take maxIncidents
    """
    
    # Execute the query against the Log Analytics workspace
    results = rest.execute_la_query(base_object, query, lookback_days)
    
    return results

def analyze_similar_incidents(similar_incidents_obj, similar_incidents_data, current_incident):
    """
    Analyze the results from the similar incidents search.
    
    This populates the SimilarIncidentsModule object with statistics and insights.
    """
    # Populate basic stats
    similar_incidents_obj.DetailedResults = similar_incidents_data
    similar_incidents_obj.SimilarIncidentsCount = len(similar_incidents_data)
    similar_incidents_obj.SimilarIncidentsFound = len(similar_incidents_data) > 0
    
    # If no similar incidents found, we're done
    if not similar_incidents_obj.SimilarIncidentsFound:
        return
    
    # Classification stats
    similar_incidents_obj.TruePositiveCount = sum(1 for incident in similar_incidents_data 
                                                if incident.get('Classification') == 'TruePositive')
    similar_incidents_obj.FalsePositiveCount = sum(1 for incident in similar_incidents_data 
                                                 if incident.get('Classification') == 'FalsePositive' 
                                                 or incident.get('Classification') == 'Informational')
    similar_incidents_obj.BenignPositiveCount = sum(1 for incident in similar_incidents_data 
                                                  if incident.get('Classification') == 'BenignPositive')
    similar_incidents_obj.UnresolvedCount = sum(1 for incident in similar_incidents_data 
                                              if incident.get('Classification') is None 
                                              or incident.get('Classification') == '')
    
    # Get the highest similarity score
    similar_incidents_obj.HighestSimilarityScore = max([incident.get('SimilarityScore', 0) 
                                                     for incident in similar_incidents_data], default=0)
    
    # Find resolution times for closed incidents
    resolution_times = []
    for incident in similar_incidents_data:
        if incident.get('Status') == 'Closed' and incident.get('ResolutionTime') and incident.get('CreatedTime'):
            try:
                created = datetime.strptime(incident.get('CreatedTime'), "%Y-%m-%dT%H:%M:%S.%fZ")
                resolved = datetime.strptime(incident.get('ResolutionTime'), "%Y-%m-%dT%H:%M:%S.%fZ")
                resolution_time_hours = (resolved - created).total_seconds() / 3600
                resolution_times.append(resolution_time_hours)
            except ValueError:
                # Handle possible date format variations
                pass
    
    # Calculate average resolution time
    similar_incidents_obj.AverageResolutionTime = statistics.mean(resolution_times) if resolution_times else 0
    
    # Aggregate incidents by title for pattern recognition
    title_counts = {}
    for incident in similar_incidents_data:
        title = incident.get('Title', '')
        if title in title_counts:
            title_counts[title] += 1
        else:
            title_counts[title] = 1
    
    # Get most common title
    similar_incidents_obj.MostCommonTitle = max(title_counts.items(), key=lambda x: x[1])[0] if title_counts else ""
    
    # Aggregate incidents by tactics
    tactic_counts = {}
    for incident in similar_incidents_data:
        tactics = incident.get('Tactics', [])
        if isinstance(tactics, list):
            for tactic in tactics:
                if tactic in tactic_counts:
                    tactic_counts[tactic] += 1
                else:
                    tactic_counts[tactic] = 1
    
    # Get most common tactics
    sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
    similar_incidents_obj.MostCommonTactics = [tactic[0] for tactic in sorted_tactics[:5]] if sorted_tactics else []
    
    # Group incidents by title for easy access
    similar_incidents_obj.SimilarIncidentsByTitle = {}
    for incident in similar_incidents_data:
        title = incident.get('Title', '')
        if title not in similar_incidents_obj.SimilarIncidentsByTitle:
            similar_incidents_obj.SimilarIncidentsByTitle[title] = []
        similar_incidents_obj.SimilarIncidentsByTitle[title].append(incident)
    
    # Group incidents by tactic for easy access
    similar_incidents_obj.SimilarIncidentsByTactic = {}
    for incident in similar_incidents_data:
        tactics = incident.get('Tactics', [])
        if isinstance(tactics, list):
            for tactic in tactics:
                if tactic not in similar_incidents_obj.SimilarIncidentsByTactic:
                    similar_incidents_obj.SimilarIncidentsByTactic[tactic] = []
                similar_incidents_obj.SimilarIncidentsByTactic[tactic].append(incident)
    
    # Group incidents by entity type for correlation
    similar_incidents_obj.SimilarIncidentsByEntity = {}
    for entity_type in ['accounts', 'ips', 'hosts', 'domains', 'filehashes']:
        if current_incident['entities'][entity_type]:
            similar_incidents_obj.SimilarIncidentsByEntity[entity_type] = []
            for entity in current_incident['entities'][entity_type]:
                matching_count = 0
                for incident in similar_incidents_data:
                    entity_field = f"{entity_type.capitalize()}Entities"
                    if entity_field in incident and entity in incident[entity_field]:
                        matching_count += 1
                
                similar_incidents_obj.SimilarIncidentsByEntity[entity_type].append({
                    'EntityValue': entity,
                    'IncidentCount': matching_count
                })

def add_incident_comment(base_object, similar_incidents):
    """
    Add a comment to the incident with the similar incidents information.
    """
    if not similar_incidents.SimilarIncidentsFound:
        comment = "<h3>Similar Incidents Module</h3>No similar incidents were found."
        rest.add_incident_comment(base_object, comment)
        return
    
    # Create HTML tables for the detailed results
    # Convert all incident URLs to hyperlinks for better usability
    linked_incidents = []
    for incident in similar_incidents.DetailedResults:
        incident_copy = incident.copy()
        if 'IncidentUrl' in incident_copy and incident_copy['IncidentUrl']:
            incident_copy['IncidentNumber'] = f"<a href='{incident_copy['IncidentUrl']}' target='_blank'>{incident_copy['IncidentNumber']}</a>"
        linked_incidents.append(incident_copy)
    
    incident_table = data.list_to_html_table(
        linked_incidents, 
        max_rows=20, 
        columns=['IncidentNumber', 'Title', 'Severity', 'Status', 'Classification', 'SimilarityScore'],
        escape_html=False,
        index=False
    )
    
    # Format the comment
    comment = f"<h3>Similar Incidents Module</h3>"
    comment += f"Found {similar_incidents.SimilarIncidentsCount} similar incidents:<br>"
    comment += f"<ul>"
    comment += f"<li>True Positives: {similar_incidents.TruePositiveCount}</li>"
    comment += f"<li>False Positives: {similar_incidents.FalsePositiveCount}</li>"
    comment += f"<li>Benign Positives: {similar_incidents.BenignPositiveCount}</li>"
    comment += f"<li>Unresolved: {similar_incidents.UnresolvedCount}</li>"
    
    if similar_incidents.AverageResolutionTime > 0:
        comment += f"<li>Average Resolution Time: {similar_incidents.AverageResolutionTime:.2f} hours</li>"
    
    if similar_incidents.MostCommonTactics:
        comment += f"<li>Most Common Tactics: {', '.join(similar_incidents.MostCommonTactics)}</li>"
    
    comment += f"</ul>"
    
    # Add detailed incidents table
    comment += f"<h4>Similar Incidents</h4>{incident_table}"
    
    # Add the comment to the incident
    rest.add_incident_comment(base_object, comment)