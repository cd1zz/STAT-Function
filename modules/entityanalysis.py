from classes import BaseModule, Response, EntityAnalysisModule, STATError
from shared import rest, data
import json
import logging
import traceback
import time

def execute_entityanalysis_module(req_body):
    """
    Extract and analyze entities from similar incidents.
    
    Inputs: 
    - SimilarIncidentsData: Output from similarincidents module
    - AddIncidentComments: Whether to add comments to incident
    - AddIncidentTask: Whether to add a task to incident
    - IncidentTaskInstructions: Instructions for the added task
    - MinEntityFrequency: Minimum frequency for an entity to be considered high frequency
    """
    # Initialize base module
    base_object = BaseModule()
    base_object.load_from_input(req_body['BaseModuleBody'])
    
    # Initialize entity analysis module
    entity_analysis = EntityAnalysisModule()
    
    # Get parameters
    min_entity_frequency = req_body.get('MinEntityFrequency', 2)
    max_retries = req_body.get('MaxRetries', 3)
    retry_delay = req_body.get('RetryDelay', 5)
    use_kql_fallback = req_body.get('UseKQLFallback', True)
    api_version = req_body.get('APIVersion', '2025-03-01')
    
    # Load data from the similar incidents module
    similar_incidents_data = req_body.get('SimilarIncidentsData', {})
    if not similar_incidents_data:
        raise STATError('No similar incidents data provided for entity analysis', {}, 400)
    
    detailed_results = similar_incidents_data.get('DetailedResults', [])
    entity_analysis.AnalyzedIncidentsCount = len(detailed_results)
    
    if entity_analysis.AnalyzedIncidentsCount == 0:
        return Response(entity_analysis)
    
    # Process and analyze entities from incidents
    extract_entities_from_incidents(
        base_object, 
        entity_analysis, 
        detailed_results, 
        max_retries, 
        retry_delay, 
        use_kql_fallback,
        api_version
    )
    
    # Find relationships between entities
    analyze_entity_relationships(entity_analysis)
    
    # Calculate entity frequencies and identify patterns
    analyze_entity_frequencies(entity_analysis, min_entity_frequency)
    
    # Calculate common entity combinations
    find_common_entity_combinations(entity_analysis, min_entity_frequency)
    
    # Add comments to the incident if requested
    if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
        add_incident_comment(base_object, entity_analysis)
    
    # Add task to the incident if requested
    if req_body.get('AddIncidentTask', False) and entity_analysis.AnalyzedEntitiesCount > 0 and base_object.IncidentAvailable:
        task_result = rest.add_incident_task(
            base_object, 
            'Review Entity Patterns Across Similar Incidents', 
            req_body.get('IncidentTaskInstructions', 'Review entity patterns across similar incidents to identify common threats')
        )
    
    return Response(entity_analysis)

def extract_entities_from_incidents(
    base_object, 
    entity_analysis, 
    incidents, 
    max_retries=3, 
    retry_delay=5, 
    use_kql_fallback=True,
    api_version='2025-03-01'
):
    """
    Extract entities from each incident and organize them by type.
    Implements multiple approaches with fallbacks when primary methods fail.
    """
    # Initialize entity tracking structures
    for entity_type in entity_analysis.EntityTypes:
        entity_analysis.EntitiesByType[entity_type] = []
    
    entity_analysis.EntityTypesFound = []
    all_entities_count = 0
    
    # Add debug logging
    logging.info(f"Starting entity extraction for {len(incidents)} incidents")
    
    # Process each incident to extract entities
    for incident in incidents:
        # Extract incident ID correctly - check different possible fields
        incident_id = None
        if 'IncidentId' in incident:
            incident_id = incident['IncidentId']
        elif 'IncidentName' in incident:
            incident_id = incident['IncidentName']
        elif 'id' in incident:
            incident_id = incident['id']
        
        # Debug: Log the incident ID
        logging.info(f"Processing incident: {incident_id}")
        
        if not incident_id:
            logging.warning(f"Could not find incident ID in incident data")
            continue
        
        # Try multiple approaches to extract entities
        entities = []
        
        # Approach 1: Use direct REST API entity extraction
        entities = get_entities_via_api(base_object, incident_id, max_retries, retry_delay, api_version)
        
        # Approach 2: If REST API fails and no entities found, try expansion ID approach
        if not entities and use_kql_fallback:
            entities = get_entities_via_expansion(base_object, incident_id, max_retries, retry_delay)
        
        # Approach 3: If both direct methods fail, try KQL query fallback
        if not entities and use_kql_fallback:
            entities = get_entities_via_kql(base_object, incident)
        
        # Add extracted entities to our analysis
        if entities:
            logging.info(f"Successfully extracted {len(entities)} entities for incident {incident_id}")
            process_incident_entities(entity_analysis, entities, incident_id)
            all_entities_count += len(entities)
        else:
            logging.warning(f"No entities found for incident {incident_id} after all extraction attempts")
    
    entity_analysis.AnalyzedEntitiesCount = all_entities_count
    logging.info(f"Total entities analyzed: {all_entities_count}")
    
    # Determine which entity types were found
    for entity_type in entity_analysis.EntityTypes:
        if entity_analysis.EntitiesByType.get(entity_type) and len(entity_analysis.EntitiesByType[entity_type]) > 0:
            entity_analysis.EntityTypesFound.append(entity_type)

def get_entities_via_api(base_object, incident_id, max_retries=3, retry_delay=5, api_version='2025-03-01'):
    """
    Get entities for a specific incident using the direct REST API approach.
    
    Args:
        base_object: The BaseModule object containing connection information
        incident_id: The ID of the incident to retrieve entities for
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        api_version: API version to use
        
    Returns:
        List of entity objects or empty list if failed
    """
    logging.info(f"Attempting to get entities for incident {incident_id} via direct API")
    
    # Properly format the incident ID to ensure it's a valid path
    try:
        # If it's already a full ARM ID, use it as is
        if incident_id.startswith('/subscriptions/'):
            path = f"{incident_id}/entities?api-version={api_version}"
        # If it's a GUID only, try to construct the path using the base incident ARM ID
        elif base_object.IncidentARMId:
            # Extract the base path from the current incident
            base_path = '/'.join(base_object.IncidentARMId.split('/')[:-1])
            path = f"{base_path}/{incident_id}/entities?api-version={api_version}"
        else:
            logging.error(f"Cannot construct entity path: incident_id={incident_id}, IncidentARMId={base_object.IncidentARMId}")
            return []
        
        logging.info(f"Using API path: {path}")
        
        # Implement retry logic
        for attempt in range(max_retries):
            try:
                response = rest.rest_call_post(base_object, 'arm', path, {})
                
                # Check if the request was successful
                if response.status_code == 200:
                    # Parse the response content
                    content = json.loads(response.content)
                    
                    # Extract entities from the response
                    if 'value' in content:
                        entities = content['value']
                        logging.info(f"Successfully retrieved {len(entities)} entities via API")
                        return entities
                    else:
                        logging.warning(f"Response contained no 'value' key: {json.dumps(content, indent=2)}")
                else:
                    logging.warning(f"API returned non-200 status: {response.status_code}")
                
                # Wait before retrying
                if attempt < max_retries - 1:
                    logging.info(f"Retrying API call after {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
            
            except Exception as e:
                logging.error(f"Exception in API-based entity extraction: {str(e)}")
                if attempt < max_retries - 1:
                    logging.info(f"Retrying after {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"All retry attempts failed for API-based extraction")
                    logging.error(traceback.format_exc())
    
    except Exception as e:
        logging.error(f"Failed to extract entities via API: {str(e)}")
        logging.error(traceback.format_exc())
    
    return []

def get_entities_via_expansion(base_object, incident_id, max_retries=3, retry_delay=5):
    """
    Get entities using the undocumented expansion ID approach.
    This is a fallback when the standard API fails.
    
    Args:
        base_object: The BaseModule object
        incident_id: The incident ID
        max_retries: Maximum retry attempts
        retry_delay: Delay between retries
    
    Returns:
        List of entities or empty list if failed
    """
    logging.info(f"Attempting to get entities for incident {incident_id} via expansion ID approach")
    
    try:
        # First get the security alert ID from incident relations
        if base_object.IncidentARMId:
            base_path = '/'.join(base_object.IncidentARMId.split('/')[:-1])
            relations_path = f"{base_path}/{incident_id}/relations?api-version=2025-03-01"
            
            logging.info(f"Getting incident relations: {relations_path}")
            
            for attempt in range(max_retries):
                try:
                    relations_response = rest.rest_call_get(base_object, 'arm', relations_path)
                    
                    if relations_response.status_code == 200:
                        relations_content = json.loads(relations_response.content)
                        
                        # Find the security alert relation
                        security_alert_id = None
                        if 'value' in relations_content:
                            for relation in relations_content['value']:
                                if relation.get('properties', {}).get('relatedResourceType') == 'Microsoft.SecurityInsights/Alerts':
                                    security_alert_id = relation.get('properties', {}).get('relatedResourceName')
                                    break
                        
                        if security_alert_id:
                            logging.info(f"Found SecurityAlertId: {security_alert_id}")
                            
                            # Now use the expansion ID approach
                            expansion_id = "98b974fd-cc64-48b8-9bd0-3a209f5b944b"  # Special hardcoded GUID
                            expand_path = f"{base_path}/providers/Microsoft.SecurityInsights/entities/{security_alert_id}/expand?api-version=2025-03-01"
                            expand_body = {'expansionId': expansion_id}
                            
                            logging.info(f"Using expand path: {expand_path}")
                            
                            expand_response = rest.rest_call_post(base_object, 'arm', expand_path, expand_body)
                            
                            if expand_response.status_code == 200:
                                expand_content = json.loads(expand_response.content)
                                if 'value' in expand_content:
                                    entities = expand_content['value']
                                    logging.info(f"Successfully retrieved {len(entities)} entities via expansion")
                                    return entities
                            else:
                                logging.warning(f"Expansion request failed with status {expand_response.status_code}")
                        else:
                            logging.warning("No SecurityAlert relation found in incident relations")
                    
                    # Retry logic
                    if attempt < max_retries - 1:
                        logging.info(f"Retrying expansion approach after {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                        time.sleep(retry_delay)
                
                except Exception as e:
                    logging.error(f"Exception in expansion-based extraction: {str(e)}")
                    if attempt < max_retries - 1:
                        logging.info(f"Retrying after {retry_delay} seconds")
                        time.sleep(retry_delay)
                    else:
                        logging.error(f"All retry attempts failed for expansion-based extraction")
    
    except Exception as e:
        logging.error(f"Failed to extract entities via expansion approach: {str(e)}")
        logging.error(traceback.format_exc())
    
    return []

def get_entities_via_kql(base_object, incident):
    """
    Fallback approach to extract entities using KQL queries.
    This approach queries the SecurityAlert table directly.
    """
    logging.info("Attempting to extract entities via KQL query fallback")
    
    entities = []
    
    try:
        # Get incident number or title for correlation
        incident_number = incident.get('IncidentNumber')
        incident_title = incident.get('Title')
        
        # If we have an incident number or title, we can try to find related alerts
        if incident_number or incident_title:
            # Construct KQL query to find related alerts with entities
            if incident_number:
                # Using correct schema columns as per provided information
                query = f"""
                SecurityIncident
                | where IncidentNumber == {incident_number}
                | project IncidentName, AlertIds
                | mv-expand AlertIds
                | join kind=inner (
                    SecurityAlert
                    | where TimeGenerated > ago(14d)
                    | extend AlertId = SystemAlertId
                ) on $left.AlertIds == $right.AlertId
                | project TimeGenerated, AlertName, AlertSeverity, Entities
                | where isnotempty(Entities)
                | extend EntitiesObj = parse_json(Entities)
                | mv-expand EntitiesObj
                | extend EntityType = tostring(EntitiesObj.Type)
                | project TimeGenerated, AlertName, AlertSeverity, EntityType, EntityDetails = EntitiesObj
                | limit 50
                """
            else:
                # Use title as a fallback (less precise)
                sanitized_title = incident_title.replace("'", "''")
                query = f"""
                SecurityAlert
                | where TimeGenerated > ago(14d)
                | where AlertName has '{sanitized_title}'
                | project TimeGenerated, AlertName, AlertSeverity, Entities
                | where isnotempty(Entities)
                | extend EntitiesObj = parse_json(Entities)
                | mv-expand EntitiesObj
                | extend EntityType = tostring(EntitiesObj.Type)
                | project TimeGenerated, AlertName, AlertSeverity, EntityType, EntityDetails = EntitiesObj
                | limit 50
                """
            
            # Execute the KQL query with reduced time range
            try:
                results = rest.execute_la_query(base_object, query, 14)
                logging.info(f"KQL query returned {len(results)} records")
                
                if results:
                    # Process each entity into our standard format
                    for result in results:
                        if 'EntityDetails' in result:
                            entity_data = result['EntityDetails']
                            entity_type = result.get('EntityType', '').lower()
                            
                            # Convert from KQL result format to the standard API format
                            entity_obj = {
                                'kind': entity_type,
                                'properties': {}
                            }
                            
                            # Map common entity properties based on type
                            if entity_type == 'account':
                                entity_obj['properties'] = {
                                    'accountName': entity_data.get('Name'),
                                    'userPrincipalName': entity_data.get('UPNSuffix', ''),
                                    'friendlyName': entity_data.get('DisplayName', entity_data.get('Name', '')),
                                    'sid': entity_data.get('Sid', '')
                                }
                            elif entity_type == 'host':
                                entity_obj['properties'] = {
                                    'hostName': entity_data.get('HostName', entity_data.get('NetBiosName', '')),
                                    'netBiosName': entity_data.get('NetBiosName', ''),
                                    'fqdn': entity_data.get('FQDN', '')
                                }
                            elif entity_type == 'ip':
                                entity_obj['properties'] = {
                                    'address': entity_data.get('Address')
                                }
                            elif entity_type in ['dns', 'dnsresolution']:
                                entity_obj['properties'] = {
                                    'domainName': entity_data.get('DomainName')
                                }
                            elif entity_type == 'url':
                                entity_obj['properties'] = {
                                    'url': entity_data.get('Url')
                                }
                            elif entity_type == 'filehash':
                                entity_obj['properties'] = {
                                    'hashValue': entity_data.get('Value'),
                                    'algorithm': entity_data.get('Algorithm', '')
                                }
                            elif entity_type == 'file':
                                entity_obj['properties'] = {
                                    'fileName': entity_data.get('Name'),
                                    'friendlyName': entity_data.get('Name')
                                }
                            
                            entities.append(entity_obj)
                
                else:
                    logging.warning("KQL query returned no results")
                    
                    # Try a broader fallback query if the first attempts fail
                    fallback_query = """
                    SecurityAlert
                    | where TimeGenerated > ago(7d)
                    | where isnotempty(Entities)
                    | extend EntitiesObj = parse_json(Entities)
                    | mv-expand EntitiesObj
                    | extend EntityType = tostring(EntitiesObj.Type)
                    | project TimeGenerated, AlertName, AlertSeverity, EntityType, EntityDetails = EntitiesObj
                    | limit 30
                    """
                    
                    fallback_results = rest.execute_la_query(base_object, fallback_query, 7)
                    
                    if fallback_results:
                        logging.info(f"Fallback query returned {len(fallback_results)} records")
                        
                        # Process entities from fallback query (same logic as above)
                        for result in fallback_results:
                            if 'EntityDetails' in result:
                                entity_data = result['EntityDetails']
                                entity_type = result.get('EntityType', '').lower()
                                
                                entity_obj = {
                                    'kind': entity_type,
                                    'properties': entity_data
                                }
                                entities.append(entity_obj)
            
            except Exception as e:
                logging.error(f"Error executing KQL query: {str(e)}")
                
                # Add a simpler fallback query with basic structure
                try:
                    simple_query = """
                    SecurityAlert
                    | where TimeGenerated > ago(7d)
                    | where isnotempty(Entities)
                    | extend EntitiesObj = parse_json(Entities)
                    | mv-expand EntitiesObj
                    | project EntityDetails = EntitiesObj
                    | limit 20
                    """
                    
                    simple_results = rest.execute_la_query(base_object, simple_query, 7)
                    
                    if simple_results:
                        logging.info(f"Simple fallback query returned {len(simple_results)} records")
                        for result in simple_results:
                            if 'EntityDetails' in result:
                                entity_data = result['EntityDetails']
                                entity_type = entity_data.get('Type', '').lower()
                                
                                entity_obj = {
                                    'kind': entity_type,
                                    'properties': entity_data
                                }
                                entities.append(entity_obj)
                
                except Exception as simple_error:
                    logging.error(f"Even simple fallback query failed: {str(simple_error)}")
        
        else:
            logging.warning("Cannot perform KQL query: missing incident number and title")
    
    except Exception as e:
        logging.error(f"Failed to extract entities via KQL: {str(e)}")
        logging.error(traceback.format_exc())
    
    logging.info(f"KQL approach extracted {len(entities)} entities")
    return entities

def process_incident_entities(entity_analysis, incident_entities, incident_id):
    """
    Process and organize entities from a specific incident
    """
    for entity in incident_entities:
        entity_type = entity.get('kind', '').lower()
        properties = entity.get('properties', {})
        
        # Process based on entity type
        if entity_type == 'account':
            process_account_entity(entity_analysis, properties, incident_id)
        elif entity_type == 'host':
            process_host_entity(entity_analysis, properties, incident_id)
        elif entity_type == 'ip':
            process_ip_entity(entity_analysis, properties, incident_id)
        elif entity_type in ['dnsresolution', 'dns']:
            process_domain_entity(entity_analysis, properties, incident_id)
        elif entity_type == 'url':
            process_url_entity(entity_analysis, properties, incident_id)
        elif entity_type == 'filehash':
            process_filehash_entity(entity_analysis, properties, incident_id)
        elif entity_type == 'file':
            process_file_entity(entity_analysis, properties, incident_id)

def process_account_entity(entity_analysis, properties, incident_id):
    """Process account entity"""
    upn = properties.get('userPrincipalName', '')
    name = properties.get('accountName', properties.get('friendlyName', ''))
    sid = properties.get('sid', '')
    aad_id = properties.get('aadUserId', '')
    
    if upn:
        add_entity_to_analysis(entity_analysis, 'Account', upn, incident_id, 'UPN')
    if name:
        add_entity_to_analysis(entity_analysis, 'Account', name, incident_id, 'Name')
    if sid:
        add_entity_to_analysis(entity_analysis, 'Account', sid, incident_id, 'SID')
    if aad_id:
        add_entity_to_analysis(entity_analysis, 'Account', aad_id, incident_id, 'AAD ID')

def process_host_entity(entity_analysis, properties, incident_id):
    """Process host entity"""
    hostname = properties.get('hostName', properties.get('netBiosName', properties.get('friendlyName', '')))
    fqdn = properties.get('fqdn', '')
    
    if hostname:
        add_entity_to_analysis(entity_analysis, 'Host', hostname, incident_id, 'Hostname')
    if fqdn:
        add_entity_to_analysis(entity_analysis, 'Host', fqdn, incident_id, 'FQDN')

def process_ip_entity(entity_analysis, properties, incident_id):
    """Process IP entity"""
    address = properties.get('address', '')
    
    if address:
        add_entity_to_analysis(entity_analysis, 'IP', address, incident_id, 'Address')

def process_domain_entity(entity_analysis, properties, incident_id):
    """Process domain entity"""
    domain_name = properties.get('domainName', '')
    
    if domain_name:
        add_entity_to_analysis(entity_analysis, 'Domain', domain_name, incident_id, 'Domain')

def process_url_entity(entity_analysis, properties, incident_id):
    """Process URL entity"""
    url_value = properties.get('url', '')
    
    if url_value:
        add_entity_to_analysis(entity_analysis, 'URL', url_value, incident_id, 'URL')

def process_filehash_entity(entity_analysis, properties, incident_id):
    """Process file hash entity"""
    hash_value = properties.get('hashValue', '')
    algorithm = properties.get('algorithm', '')
    
    if hash_value:
        add_entity_to_analysis(entity_analysis, 'FileHash', hash_value, incident_id, algorithm)

def process_file_entity(entity_analysis, properties, incident_id):
    """Process file entity"""
    file_name = properties.get('fileName', properties.get('friendlyName', ''))
    
    if file_name:
        add_entity_to_analysis(entity_analysis, 'File', file_name, incident_id, 'FileName')

def add_entity_to_analysis(entity_analysis, entity_type, entity_value, incident_id, entity_subtype):
    """
    Add an entity to the analysis with its relationship to the incident
    """
    # Skip empty values
    if not entity_value:
        return
    
    # Normalize entity value to lowercase for consistent comparison
    entity_value = entity_value.lower()
    
    # Check if entity already exists in our collection
    existing_entities = entity_analysis.EntitiesByType.get(entity_type, [])
    for entity in existing_entities:
        if entity['value'].lower() == entity_value:
            # Entity exists, add this incident to its occurrences
            if incident_id not in entity['incidents']:
                entity['incidents'].append(incident_id)
                entity['frequency'] = len(entity['incidents'])
            return
    
    # Entity doesn't exist, add it
    new_entity = {
        'value': entity_value,
        'type': entity_type,
        'subtype': entity_subtype,
        'incidents': [incident_id],
        'frequency': 1
    }
    
    if entity_type not in entity_analysis.EntitiesByType:
        entity_analysis.EntitiesByType[entity_type] = []
    
    entity_analysis.EntitiesByType[entity_type].append(new_entity)

def analyze_entity_relationships(entity_analysis):
    """
    Analyze relationships between entities based on co-occurrence in incidents
    """
    entity_analysis.EntityRelationships = []
    
    # Create a mapping from incident ID to all entities in that incident
    incident_entities = {}
    
    for entity_type in entity_analysis.EntityTypes:
        for entity in entity_analysis.EntitiesByType.get(entity_type, []):
            for incident_id in entity['incidents']:
                if incident_id not in incident_entities:
                    incident_entities[incident_id] = []
                incident_entities[incident_id].append({
                    'type': entity_type,
                    'value': entity['value']
                })
    
    # Find relationships between entities that co-occur in incidents
    for incident_id, entities in incident_entities.items():
        for i in range(len(entities)):
            entity1 = entities[i]
            for j in range(i + 1, len(entities)):
                entity2 = entities[j]
                
                # Create a unique key for this relationship
                rel_key = f"{entity1['type']}:{entity1['value']}-{entity2['type']}:{entity2['value']}"
                
                # Check if relationship already exists
                existing_rel = None
                for rel in entity_analysis.EntityRelationships:
                    if rel['key'] == rel_key:
                        existing_rel = rel
                        break
                
                if existing_rel:
                    # Relationship exists, update it
                    if incident_id not in existing_rel['incidents']:
                        existing_rel['incidents'].append(incident_id)
                    existing_rel['co_occurrence'] = len(existing_rel['incidents'])
                else:
                    # Create new relationship
                    new_rel = {
                        'key': rel_key,
                        'entity1_type': entity1['type'],
                        'entity1_value': entity1['value'],
                        'entity2_type': entity2['type'],
                        'entity2_value': entity2['value'],
                        'incidents': [incident_id],
                        'co_occurrence': 1
                    }
                    entity_analysis.EntityRelationships.append(new_rel)

def analyze_entity_frequencies(entity_analysis, min_frequency):
    """
    Calculate entity frequencies and identify high-frequency entities
    """
    entity_analysis.EntityFrequencyCounts = {}
    high_frequency_entities = 0
    
    for entity_type in entity_analysis.EntityTypes:
        entity_analysis.EntityFrequencyCounts[entity_type] = {
            'total': 0,
            'high_frequency': 0
        }
        
        for entity in entity_analysis.EntitiesByType.get(entity_type, []):
            # Calculate frequency as the number of incidents this entity appears in
            frequency = len(entity['incidents'])
            entity['frequency'] = frequency
            
            entity_analysis.EntityFrequencyCounts[entity_type]['total'] += 1
            
            if frequency >= min_frequency:
                entity_analysis.EntityFrequencyCounts[entity_type]['high_frequency'] += 1
                high_frequency_entities += 1
    
    entity_analysis.HighFrequencyEntitiesCount = high_frequency_entities

def find_common_entity_combinations(entity_analysis, min_frequency):
    """
    Find combinations of entities that commonly appear together across incidents
    """
    # Create a mapping of incidents to their entities
    incident_to_entities = {}
    
    for entity_type in entity_analysis.EntityTypes:
        for entity in entity_analysis.EntitiesByType.get(entity_type, []):
            for incident_id in entity['incidents']:
                if incident_id not in incident_to_entities:
                    incident_to_entities[incident_id] = []
                
                incident_to_entities[incident_id].append({
                    'type': entity_type,
                    'value': entity['value']
                })
    
    # Find common combinations using a simplified approach
    entity_combinations = {}
    
    for incident_id, entities in incident_to_entities.items():
        # Consider combinations of 2 entities for simplicity
        for i in range(len(entities)):
            for j in range(i+1, len(entities)):
                # Create a pair of entities
                pair = [entities[i], entities[j]]
                pair_key = f"{pair[0]['type']}:{pair[0]['value']},{pair[1]['type']}:{pair[1]['value']}"
                
                if pair_key not in entity_combinations:
                    entity_combinations[pair_key] = {
                        'entities': pair,
                        'incidents': [incident_id],
                        'frequency': 1
                    }
                else:
                    if incident_id not in entity_combinations[pair_key]['incidents']:
                        entity_combinations[pair_key]['incidents'].append(incident_id)
                        entity_combinations[pair_key]['frequency'] += 1
    
    # Filter to combinations that meet the minimum frequency
    common_combinations = []
    for key, combo in entity_combinations.items():
        if combo['frequency'] >= min_frequency:
            common_combinations.append(combo)
    
    # Sort by frequency (descending)
    common_combinations.sort(key=lambda x: x['frequency'], reverse=True)
    
    entity_analysis.CommonEntityCombinations = common_combinations
    entity_analysis.UniquePatternsCount = len(common_combinations)

def add_incident_comment(base_object, entity_analysis):
    """
    Add a comment to the incident with the entity analysis results
    """
    # Create summary of entity analysis
    comment = f"<h3>Entity Analysis Across Similar Incidents</h3>"
    comment += f"Analyzed {entity_analysis.AnalyzedIncidentsCount} similar incidents containing {entity_analysis.AnalyzedEntitiesCount} entities.<br>"
    
    # Add summary of entity types found
    entity_types_summary = []
    for entity_type in entity_analysis.EntityTypes:
        count = len(entity_analysis.EntitiesByType.get(entity_type, []))
        if count > 0:
            entity_types_summary.append(f"{entity_type}s: {count}")
    
    comment += f"<ul>"
    comment += f"<li>Entity types found: {', '.join(entity_analysis.EntityTypesFound)}</li>"
    comment += f"<li>High frequency entities: {entity_analysis.HighFrequencyEntitiesCount}</li>"
    comment += f"<li>Common entity combinations: {entity_analysis.UniquePatternsCount}</li>"
    comment += f"</ul>"
    
    # Add high frequency entities by type
    for entity_type in entity_analysis.EntityTypes:
        entities = entity_analysis.EntitiesByType.get(entity_type, [])
        if not entities:
            continue
            
        # Get high frequency entities for this type
        high_freq_entities = [e for e in entities if e['frequency'] > 1]
        
        if high_freq_entities:
            # Sort by frequency (descending)
            high_freq_entities.sort(key=lambda x: x['frequency'], reverse=True)
            
            # Take top 10 for display
            top_entities = high_freq_entities[:10]
            
            # Format for HTML table
            table_data = []
            for entity in top_entities:
                table_data.append({
                    'Value': entity['value'],
                    'Frequency': entity['frequency'],
                    'Subtype': entity['subtype'],
                    'Incidents': ', '.join(map(str, entity['incidents']))
                })
            
            html_table = data.list_to_html_table(table_data, max_rows=10, index=False)
            
            comment += f"<h4>Common {entity_type} Entities</h4>"
            comment += html_table
    
    # Add common entity combinations
    if entity_analysis.CommonEntityCombinations:
        # Take top 10 combinations
        top_combinations = entity_analysis.CommonEntityCombinations[:10]
        
        # Format for HTML table
        combination_data = []
        for combo in top_combinations:
            entity_str = ', '.join([f"{e['type']}: {e['value']}" for e in combo['entities']])
            combination_data.append({
                'Entity Combination': entity_str,
                'Frequency': combo['frequency'],
                'Incidents': ', '.join(map(str, combo['incidents']))
            })
        
        html_table = data.list_to_html_table(combination_data, max_rows=10, index=False)
        
        comment += f"<h4>Common Entity Combinations</h4>"
        comment += html_table
    
    # Add the comment to the incident
    rest.add_incident_comment(base_object, comment)