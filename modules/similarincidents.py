from classes import BaseModule, Response, SimilarIncidentsModule, STATError
from shared import rest, data
import json
from datetime import datetime, timedelta
import statistics
import random

def execute_similarincidents_module(req_body):
    """
    Execute the Similar Incidents module to find and analyze related past incidents.
    
    This module identifies similar incidents by comparing tactics and titles,
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
    api_version = req_body.get('APIVersion', '2024-09-01')
    
    # Get match parameters
    match_by_entity = req_body.get('MatchByEntity', False)  # Entities not directly in incident
    match_by_title = req_body.get('MatchByTitle', True)
    match_by_tactics = req_body.get('MatchByTactics', True)
    
    # Check if we have an incident to compare against
    if not base_object.IncidentAvailable:
        raise STATError('There is no incident associated with this STAT triage. Unable to find similar incidents.')
    
    # Gather data from the current incident
    current_incident = get_current_incident_details(base_object, api_version)
    
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
    
    # Add LLM-friendly data if requested
    if req_body.get('PrepareLLMData', False):
        prepare_llm_data(similar_incidents, current_incident, base_object)
    
    # Add comment to the incident if requested
    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        add_incident_comment(base_object, similar_incidents)
    
    # Add task to the incident if requested and if similar incidents were found
    if req_body.get('AddIncidentTask', False) and similar_incidents.SimilarIncidentsFound and base_object.IncidentAvailable:
        task_description = req_body.get('IncidentTaskInstructions', 'Review similar incidents for patterns and resolution approaches')
        task_result = rest.add_incident_task(base_object, 'Review Similar Incidents', task_description)
    
    return Response(similar_incidents)

def get_current_incident_details(base_object, api_version):
    """
    Retrieve details about the current incident for comparison.
    """
    path = f'{base_object.IncidentARMId}?api-version={api_version}'
    current_incident = json.loads(rest.rest_call_get(base_object, 'arm', path).content)
    
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
        'createdTime': current_incident['properties'].get('createdTimeUtc', '')
    }

def search_similar_incidents(base_object, current_incident, lookback_days, similarity_threshold, max_incidents, match_by_entity, match_by_title, match_by_tactics):
    """
    Search for incidents similar to the current one.
    
    Similarity is determined by similar titles and matching tactics.
    """
    # Calculate the lookback date
    lookback_date = (datetime.now() - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Construct the KQL query to find similar incidents
    query = f"""
    let currentIncidentId = "{current_incident['id']}";
    let lookbackDate = datetime({lookback_date});
    let maxIncidents = {max_incidents};
    """
    
    # Add title and tactics if we're matching by those
    if match_by_title:
        sanitized_title = current_incident['title'].replace('"', "'")
        query += f"""
        let currentTitle = "{sanitized_title}";
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
    
    # Add data extraction and match calculation
    query += """
    | extend AdditionalDataObj = parse_json(tostring(AdditionalData))
    | extend Tactics = AdditionalDataObj.tactics
    | extend Techniques = AdditionalDataObj.techniques
    """
    
    # Add match calculation based on selected criteria
    match_conditions = []
    
    # Title matching
    if match_by_title:
        query += """
        | extend TitleSimilarity = iff(Title contains currentTitle or currentTitle contains Title, 0.8, 0.0)
        """
        match_conditions.append("TitleSimilarity")
    
    # Tactics matching
    if match_by_tactics and current_incident['tactics']:
        query += """
        | extend TacticMatchCount = array_length(set_intersect(Tactics, currentTactics))
        | extend TotalCurrentTactics = array_length(currentTactics)
        | extend TacticsMatchScore = iff(TotalCurrentTactics > 0, toreal(TacticMatchCount) / toreal(TotalCurrentTactics), 0.0)
        """
        match_conditions.append("TacticsMatchScore")
    
    # Calculate overall similarity score
    if match_conditions:
        similarity_expr = " + ".join(match_conditions)
        divisor = len(match_conditions)
        query += f"""
        | extend SimilarityScore = ({similarity_expr}) / {divisor}.0
        | where SimilarityScore >= {similarity_threshold}
        """
    else:
        # Fallback if no match conditions
        query += """
        | extend SimilarityScore = 0.0
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
             Techniques,
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
        if incident.get('Status') == 'Closed' and incident.get('ClosedTime') and incident.get('CreatedTime'):
            try:
                created = datetime.strptime(incident.get('CreatedTime'), "%Y-%m-%dT%H:%M:%S.%fZ")
                resolved = datetime.strptime(incident.get('ClosedTime'), "%Y-%m-%dT%H:%M:%S.%fZ")
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

def prepare_llm_data(similar_incidents_obj, current_incident, base_object):
    """
    Prepare LLM-friendly data structure for incident classification prediction.
    
    This creates a well-structured JSON object optimized for LLM processing
    which contains all relevant information needed to predict if an incident
    is likely a true or false positive.
    """
    # Format the current incident data
    current_incident_formatted = {
        "title": current_incident['title'],
        "severity": current_incident['severity'],
        "tactics": current_incident['tactics'],
        "description": current_incident.get('description', '')
    }
    
    # Format similar incidents with their classifications
    similar_incidents_formatted = []
    for incident in similar_incidents_obj.DetailedResults:
        # Format timestamps for better readability
        created_time = format_timestamp(incident.get('CreatedTime', ''))
        closed_time = format_timestamp(incident.get('ClosedTime', ''))
        
        formatted_incident = {
            "id": incident.get('IncidentNumber', ''),
            "title": incident.get('Title', ''),
            "severity": incident.get('Severity', ''),
            "status": incident.get('Status', ''),
            "classification": incident.get('Classification', ''),
            "classification_comment": incident.get('ClassificationComment', ''),
            "classification_reason": incident.get('ClassificationReason', ''),
            "similarity_score": incident.get('SimilarityScore', 0),
            "tactics": incident.get('Tactics', []),
            "techniques": incident.get('Techniques', []),
            "created_time": created_time,
            "closed_time": closed_time,
        }
        similar_incidents_formatted.append(formatted_incident)
    
    # Calculate classification distribution percentages
    total_classified = (similar_incidents_obj.TruePositiveCount + 
                       similar_incidents_obj.FalsePositiveCount + 
                       similar_incidents_obj.BenignPositiveCount)
    
    tp_percentage = 0
    fp_percentage = 0
    bp_percentage = 0
    
    if total_classified > 0:
        tp_percentage = (similar_incidents_obj.TruePositiveCount / total_classified) * 100
        fp_percentage = (similar_incidents_obj.FalsePositiveCount / total_classified) * 100
        bp_percentage = (similar_incidents_obj.BenignPositiveCount / total_classified) * 100
    
    # Build comprehensive statistics
    statistics = {
        "total_similar": similar_incidents_obj.SimilarIncidentsCount,
        "true_positives": {
            "count": similar_incidents_obj.TruePositiveCount,
            "percentage": round(tp_percentage, 1)
        },
        "false_positives": {
            "count": similar_incidents_obj.FalsePositiveCount,
            "percentage": round(fp_percentage, 1)
        },
        "benign_positives": {
            "count": similar_incidents_obj.BenignPositiveCount,
            "percentage": round(bp_percentage, 1)
        },
        "unresolved": similar_incidents_obj.UnresolvedCount,
        "avg_resolution_time_hours": round(similar_incidents_obj.AverageResolutionTime, 2),
        "most_common_title": similar_incidents_obj.MostCommonTitle,
        "most_common_tactics": similar_incidents_obj.MostCommonTactics,
        "highest_similarity_score": similar_incidents_obj.HighestSimilarityScore
    }
    
    # Get entity data for LLM context
    entity_data = {
        "accounts": extract_entity_data(base_object.Accounts, "Account", 5),
        "hosts": extract_entity_data(base_object.Hosts, "Host", 5),
        "ips": extract_entity_data(base_object.IPs, "IP", 5),
        "domains": extract_entity_data(base_object.Domains, "Domain", 5),
        "files": extract_entity_data(base_object.Files, "File", 5),
        "file_hashes": extract_entity_data(base_object.FileHashes, "FileHash", 5)
    }
    
    # Assemble the complete LLM data object
    llm_data = {
        "meta": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "incident_id": current_incident.get('id', ''),
            "workspace_name": base_object.WorkspaceName
        },
        "current_incident": current_incident_formatted,
        "similar_incidents": similar_incidents_formatted,
        "statistics": statistics,
        "entities": entity_data
    }
    
    # Add the data to our module object
    similar_incidents_obj.LLMData = llm_data
    
    # Optionally, add a comment with the JSON data
    if base_object.IncidentAvailable:
        comment = f"<h3>LLM Data for Incident Classification</h3>"
        comment += f"<p>Generated data for LLM analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        comment += f"<p>Found {similar_incidents_obj.SimilarIncidentsCount} similar incidents with classifications:<br>"
        comment += f"• True Positives: {similar_incidents_obj.TruePositiveCount} ({round(tp_percentage, 1)}%)<br>"
        comment += f"• False Positives: {similar_incidents_obj.FalsePositiveCount} ({round(fp_percentage, 1)}%)<br>"
        comment += f"• Benign Positives: {similar_incidents_obj.BenignPositiveCount} ({round(bp_percentage, 1)}%)</p>"
        
        # Add a prompt example for security analyst
        comment += f"<h4>Example LLM Prompt:</h4>"
        comment += f"<pre>You are a security incident analyst. Based on the attached data about a security incident and similar past incidents, determine if this is likely a true positive or false positive alert. Provide your analysis with confidence level and reasoning.</pre>"
        
        rest.add_incident_comment(base_object, comment)
    
    return llm_data

def extract_entity_data(entity_list, entity_type, max_entities=5):
    """
    Extract the most relevant entity data in a format suitable for LLM analysis
    """
    formatted_entities = []
    
    if not entity_list or len(entity_list) == 0:
        return formatted_entities
    
    # Take the first max_entities items (or all if fewer)
    for entity in entity_list[:max_entities]:
        entity_data = {}
        
        if entity_type == "Account":
            entity_data = {
                "upn": entity.get('userPrincipalName', ''),
                "name": entity.get('displayName', ''),
                "department": entity.get('department', ''),
                "job_title": entity.get('jobTitle', ''),
                "is_privileged": entity.get('isAADPrivileged', False),
                "mfa_registered": entity.get('isMfaRegistered', 'Unknown')
            }
        elif entity_type == "Host":
            entity_data = {
                "hostname": entity.get('HostName', ''),
                "fqdn": entity.get('FQDN', ''),
                "dns_domain": entity.get('DnsDomain', '')
            }
        elif entity_type == "IP":
            geo_data = entity.get('GeoData', {})
            entity_data = {
                "address": entity.get('Address', ''),
                "country": geo_data.get('country', ''),
                "city": geo_data.get('city', ''),
                "organization": geo_data.get('organization', '')
            }
        elif entity_type == "Domain":
            entity_data = {
                "domain": entity.get('Domain', '')
            }
        elif entity_type == "File":
            entity_data = {
                "filename": entity.get('FileName', '')
            }
        elif entity_type == "FileHash":
            entity_data = {
                "hash": entity.get('FileHash', ''),
                "algorithm": entity.get('Algorithm', '')
            }
        
        formatted_entities.append(entity_data)
    
    return formatted_entities

def format_timestamp(timestamp_str):
    """Format timestamp for better readability"""
    if not timestamp_str:
        return ""
    
    try:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp_str

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
    
    # Add prediction section if LLM data is available
    if hasattr(similar_incidents, 'LLMData'):
        total_classified = (similar_incidents.TruePositiveCount + 
                           similar_incidents.FalsePositiveCount + 
                           similar_incidents.BenignPositiveCount)
        
        if total_classified > 0:
            tp_percentage = (similar_incidents.TruePositiveCount / total_classified) * 100
            fp_percentage = (similar_incidents.FalsePositiveCount / total_classified) * 100
            bp_percentage = (similar_incidents.BenignPositiveCount / total_classified) * 100
            
            comment += f"<h4>Classification Statistics</h4>"
            comment += f"<p>Based on {total_classified} classified similar incidents:</p>"
            comment += f"<ul>"
            comment += f"<li>True Positive likelihood: {round(tp_percentage, 1)}%</li>"
            comment += f"<li>False Positive likelihood: {round(fp_percentage, 1)}%</li>"
            comment += f"<li>Benign Positive likelihood: {round(bp_percentage, 1)}%</li>"
            comment += f"</ul>"
    
    # Add the comment to the incident
    rest.add_incident_comment(base_object, comment)