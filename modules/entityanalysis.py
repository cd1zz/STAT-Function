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
    # Use stable API version instead of preview version
    api_version = req_body.get('APIVersion', '2024-09-01')
    
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
    api_version='2024-09-01'
):
    """
    Extract entities from each incident and organize them by type.
    Implements direct API approach with proper error handling.
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
        
        # Try to extract entities using direct API
        entities = get_entities_via_api(base_object, incident_id, max_retries, retry_delay, api_version)
        
        # Add extracted entities to our analysis
        if entities:
            logging.info(f"Successfully extracted {len(entities)} entities for incident {incident_id}")
            process_incident_entities(entity_analysis, entities, incident_id)
            all_entities_count += len(entities)
        else:
            logging.warning(f"No entities found for incident {incident_id}")
    
    entity_analysis.AnalyzedEntitiesCount = all_entities_count
    logging.info(f"Total entities analyzed: {all_entities_count}")
    
    # Determine which entity types were found
    for entity_type in entity_analysis.EntityTypes:
        if entity_analysis.EntitiesByType.get(entity_type) and len(entity_analysis.EntitiesByType[entity_type]) > 0:
            entity_analysis.EntityTypesFound.append(entity_type)

def get_entities_via_api(base_object, incident_id, max_retries=3, retry_delay=5, api_version='2024-09-01'):
    """
    Get entities for a specific incident using the direct REST API approach.
    Uses stable API version and proper path construction.
    
    Args:
        base_object: The BaseModule object containing connection information
        incident_id: The ID of the incident to retrieve entities for
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        api_version: API version to use (using stable version)
        
    Returns:
        List of entity objects or empty list if failed
    """
    logging.info(f"Attempting to get entities for incident {incident_id} via API")
    
    try:
        # Construct the proper resource path
        # The correct format requires both provider segments for Microsoft Sentinel
        if incident_id.startswith('/subscriptions/'):
            # It's already a full ARM ID
            path = f"{incident_id}/entities?api-version={api_version}"
        elif base_object.IncidentARMId:
            # Extract required parts from the current incident ARM ID
            parts = base_object.IncidentARMId.split('/')
            if len(parts) >= 9:
                # Standard format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/...
                subscription_id = parts[2]
                resource_group = parts[4]
                workspace = parts[8]
                
                # Construct the full path with all required provider segments
                path = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/incidents/{incident_id}/entities?api-version={api_version}"
            else:
                # Fallback to base path if structure doesn't match expected format
                base_path = '/'.join(base_object.IncidentARMId.split('/')[:-1]) 
                path = f"{base_path}/{incident_id}/entities?api-version={api_version}"
        else:
            logging.error(f"Cannot construct entity path: incident_id={incident_id}, IncidentARMId not available")
            return []
        
        logging.info(f"Using API path: {path}")
        
        # Implement retry with exponential backoff
        for attempt in range(max_retries):
            try:
                # IMPORTANT: Use POST method (not GET) as required by the API
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
                    # Handle the alternate response format where entities are under "entities" key
                    elif 'entities' in content:
                        entities = content['entities']
                        logging.info(f"Successfully retrieved {len(entities)} entities via alternate API structure")
                        return entities
                    else:
                        logging.warning(f"Response contained no 'value' or 'entities' key: {str(content)[:200]}")
                else:
                    logging.warning(f"API returned non-200 status: {response.status_code}")
                    # Check if it's a rate limiting issue
                    if response.status_code == 429 and 'Retry-After' in response.headers:
                        retry_after = int(response.headers.get('Retry-After', retry_delay))
                        logging.info(f"Rate limited. Waiting for {retry_after} seconds before retry")
                        time.sleep(retry_after)
                        continue
                
                # Calculate backoff time with jitter for non-429 errors
                backoff_time = min(retry_delay * (2 ** attempt), 60)  # Cap at 60 seconds
                # Apply jitter to avoid thundering herd problem (±20%)
                jitter = backoff_time * 0.2 * (2 * (0.5 - random.random()))
                wait_time = max(1, backoff_time + jitter)
                
                # Only retry if not the last attempt
                if attempt < max_retries - 1:
                    logging.info(f"Retrying API call after {wait_time:.1f} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    logging.error(f"All retry attempts failed for incident {incident_id}")
            
            except Exception as e:
                logging.error(f"Exception in API-based entity extraction: {str(e)}")
                if attempt < max_retries - 1:
                    # Use exponential backoff for exceptions too
                    backoff_time = retry_delay * (2 ** attempt)
                    logging.info(f"Retrying after {backoff_time} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(backoff_time)
                else:
                    logging.error(f"All retry attempts failed for API-based extraction")
                    logging.error(traceback.format_exc())
    
    except Exception as e:
        logging.error(f"Failed to extract entities via API: {str(e)}")
        logging.error(traceback.format_exc())
    
    return []

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