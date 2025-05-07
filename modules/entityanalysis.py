from classes import BaseModule, Response, EntityAnalysisModule, STATError
from shared import rest, data
import json
import logging
import traceback
import time
import random
from datetime import datetime

def execute_entityanalysis_module(req_body):
    """
    Extract and analyze entities from similar incidents.
    
    Inputs: 
    - SimilarIncidentsData: Output from similarincidents module
    - AddIncidentComments: Whether to add comments to incident
    - AddIncidentTask: Whether to add a task to incident
    - IncidentTaskInstructions: Instructions for the added task
    - MinEntityFrequency: Minimum frequency for an entity to be considered high frequency
    - PrepareLLMData: Whether to prepare data for LLM analysis
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
        api_version
    )
    
    # Extract email entities from the raw data
    extract_email_entities_from_raw_data(base_object, entity_analysis)
    
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
    
    # Add the condensed summary for LLM processing if requested
    if req_body.get('PrepareLLMData', False):
        # Extract classification patterns
        classification_patterns = extract_classification_patterns(entity_analysis, detailed_results)
        
        # Deduplicate while preserving important patterns
        deduplicated_data = deduplicate_entities(
            entity_analysis, 
            classification_patterns,
            min_entity_frequency
        )
        
        # Generate the final summary
        llm_summary = generate_llm_friendly_summary(
            entity_analysis,
            deduplicated_data
        )
        
        # Add the current incident entities for comparison
        llm_summary['current_incident']['entities'] = extract_current_incident_entities(base_object)
        
        # Store the condensed data in the module response
        entity_analysis.LLMData = llm_summary
        
        # Optionally add a comment to the incident with the LLM-ready data
        if req_body.get('AddIncidentComments', True) and base_object.IncidentAvailable:
            llm_comment = f"<h3>Entity Analysis for LLM Classification</h3>"
            llm_comment += f"<p>Generated a condensed entity analysis for LLM processing.</p>"
            llm_comment += f"<p>Found {len(classification_patterns['true_positive_patterns'])} true positive entity types "
            llm_comment += f"and {len(classification_patterns['false_positive_patterns'])} false positive entity types "
            llm_comment += f"across {entity_analysis.AnalyzedIncidentsCount} similar incidents.</p>"
            
            rest.add_incident_comment(base_object, llm_comment)
    
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
        # Add a check for email entities
        elif entity_type == 'email':
            process_email_entity(entity_analysis, properties, incident_id)
        # Process entities from RawEntity that might be emails
        elif 'friendlyName' in properties and any(email_prop in properties for email_prop in 
              ['recipient', 'p1Sender', 'p2Sender', 'networkMessageId', 'subject']):
            process_email_entity(entity_analysis, properties, incident_id)

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

def process_email_entity(entity_analysis, properties, incident_id):
    """Process email entity with all pertinent data points"""
    # Extract all relevant email properties
    recipient = properties.get('recipient', '')
    p1_sender = properties.get('p1Sender', '')
    p1_sender_domain = properties.get('p1SenderDomain', '')
    sender_ip = properties.get('senderIP', '')
    p2_sender = properties.get('p2Sender', '')
    p2_sender_display_name = properties.get('p2SenderDisplayName', '')
    p2_sender_domain = properties.get('p2SenderDomain', '')
    receive_date = properties.get('receiveDate', '')
    network_message_id = properties.get('networkMessageId', '')
    internet_message_id = properties.get('internetMessageId', '')
    subject = properties.get('subject', '')
    delivery_action = properties.get('deliveryAction', '')
    language = properties.get('language', '')
    
    # Add each relevant email property to analysis
    if recipient:
        add_entity_to_analysis(entity_analysis, 'Email', recipient, incident_id, 'Recipient')
    if p1_sender:
        add_entity_to_analysis(entity_analysis, 'Email', p1_sender, incident_id, 'Sender')
    if p1_sender_domain:
        add_entity_to_analysis(entity_analysis, 'Email', p1_sender_domain, incident_id, 'SenderDomain')
    if sender_ip:
        add_entity_to_analysis(entity_analysis, 'Email', sender_ip, incident_id, 'SenderIP')
    if subject:
        add_entity_to_analysis(entity_analysis, 'Email', subject, incident_id, 'Subject')
    if network_message_id:
        add_entity_to_analysis(entity_analysis, 'Email', network_message_id, incident_id, 'NetworkMessageID')
    if internet_message_id:
        add_entity_to_analysis(entity_analysis, 'Email', internet_message_id, incident_id, 'InternetMessageID')
    
    # Store the complete email object for more detailed analysis
    email_object = {
        'recipient': recipient,
        'p1Sender': p1_sender,
        'p1SenderDomain': p1_sender_domain,
        'senderIP': sender_ip,
        'p2Sender': p2_sender,
        'p2SenderDisplayName': p2_sender_display_name,
        'p2SenderDomain': p2_sender_domain,
        'receiveDate': receive_date,
        'networkMessageId': network_message_id,
        'internetMessageId': internet_message_id,
        'subject': subject,
        'deliveryAction': delivery_action,
        'language': language
    }
    
    # Add the complete email object to a separate collection for full context
    if 'EmailObjects' not in entity_analysis.__dict__:
        entity_analysis.EmailObjects = []
    
    entity_analysis.EmailObjects.append({
        'properties': email_object,
        'incident_id': incident_id
    })

def extract_email_entities_from_raw_data(base_object, entity_analysis):
    """
    Extract email entities from the OtherEntities section of the raw data
    """
    logging.info("Extracting email entities from OtherEntities")
    
    # Check if OtherEntities exists in the base object
    if hasattr(base_object, 'OtherEntities') and base_object.OtherEntities:
        for entity in base_object.OtherEntities:
            raw_entity = entity.get('RawEntity', {})
            
            # Check if this looks like an email entity
            if any(email_prop in raw_entity for email_prop in 
                  ['recipient', 'p1Sender', 'p2Sender', 'networkMessageId', 'subject']):
                
                # Process as an email entity
                process_email_entity(entity_analysis, raw_entity, 'current_incident')
                
                logging.info(f"Found and processed email entity: {raw_entity.get('networkMessageId', 'unknown')}")

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

def extract_classification_patterns(entity_analysis, detailed_results):
    """
    Extract patterns that correlate with true/false positive classifications from historical incidents
    """
    # Group incidents by classification
    true_positive_incidents = []
    false_positive_incidents = []
    
    # Get classifications from historical data
    for incident in detailed_results:
        if incident.get('Classification') == 'TruePositive':
            true_positive_incidents.append(incident)
        elif incident.get('Classification') in ['FalsePositive', 'Informational', 'BenignPositive']:
            false_positive_incidents.append(incident)
    
    # Extract entities associated with each classification
    tp_entities = {entity_type: [] for entity_type in entity_analysis.EntityTypes}
    fp_entities = {entity_type: [] for entity_type in entity_analysis.EntityTypes}
    
    # Populate entity lists by classification
    for entity_type in entity_analysis.EntityTypesFound:
        for entity in entity_analysis.EntitiesByType.get(entity_type, []):
            # Check if this entity appears more in TP or FP incidents
            tp_count = sum(1 for incident_id in entity['incidents'] 
                           if any(incident.get('IncidentId', '') == incident_id or 
                                  incident.get('id', '') == incident_id or
                                  incident.get('IncidentName', '') == incident_id 
                                  for incident in true_positive_incidents))
            
            fp_count = sum(1 for incident_id in entity['incidents'] 
                           if any(incident.get('IncidentId', '') == incident_id or 
                                  incident.get('id', '') == incident_id or
                                  incident.get('IncidentName', '') == incident_id 
                                  for incident in false_positive_incidents))
            
            # Calculate classification ratio
            total = tp_count + fp_count
            if total > 0:
                tp_ratio = tp_count / total
                fp_ratio = fp_count / total
                
                # Add classification data to entity
                entity_with_class = entity.copy()
                entity_with_class['classification_data'] = {
                    'tp_count': tp_count,
                    'fp_count': fp_count,
                    'tp_ratio': tp_ratio,
                    'fp_ratio': fp_ratio,
                    'classification_confidence': max(tp_ratio, fp_ratio)
                }
                
                # Add to appropriate list
                if tp_ratio > fp_ratio:
                    tp_entities[entity_type].append(entity_with_class)
                else:
                    fp_entities[entity_type].append(entity_with_class)
    
    return {
        'true_positive_patterns': tp_entities,
        'false_positive_patterns': fp_entities
    }

def deduplicate_entities(entity_analysis, classification_patterns, min_frequency=2):
    """
    Deduplicate entities while preserving classification patterns
    """
    deduplicated_data = {
        'high_value_entities': {},
        'entity_relationships': []
    }
    
    # Extract high-value entities by type (those with strong classification signals)
    for entity_type in entity_analysis.EntityTypesFound:
        # Start with high-frequency entities
        high_freq_entities = [e for e in entity_analysis.EntitiesByType.get(entity_type, []) 
                             if e['frequency'] >= min_frequency]
        
        # For each entity type, keep entities with strong classification signals
        tp_entities = classification_patterns['true_positive_patterns'].get(entity_type, [])
        fp_entities = classification_patterns['false_positive_patterns'].get(entity_type, [])
        
        # Sort by classification confidence
        tp_entities.sort(key=lambda x: x.get('classification_data', {}).get('classification_confidence', 0), reverse=True)
        fp_entities.sort(key=lambda x: x.get('classification_data', {}).get('classification_confidence', 0), reverse=True)
        
        # Keep top N of each, where N scales with entity type importance
        max_entities = {
            'Account': 10,
            'IP': 10,
            'Email': 10,
            'Domain': 8,
            'URL': 8,
            'FileHash': 6,
            'File': 6,
            'Host': 10
        }.get(entity_type, 5)
        
        # Combine TP and FP while respecting limits
        tp_limit = max(1, max_entities // 2)
        fp_limit = max(1, max_entities // 2)
        
        deduplicated_data['high_value_entities'][entity_type] = {
            'true_positive': tp_entities[:tp_limit],
            'false_positive': fp_entities[:fp_limit]
        }
    
    # Extract high-value entity relationships (those with strong classification patterns)
    if hasattr(entity_analysis, 'EntityRelationships'):
        # Group relationships by classification
        tp_relationships = []
        fp_relationships = []
        
        for relationship in entity_analysis.EntityRelationships:
            if relationship['co_occurrence'] >= min_frequency:
                # Check if this relationship appears more in TP or FP incidents
                tp_count = 0
                fp_count = 0
                
                for incident_id in relationship['incidents']:
                    # Check in TP incidents
                    if any(incident.get('IncidentId', '') == incident_id or 
                           incident.get('id', '') == incident_id or
                           incident.get('IncidentName', '') == incident_id 
                           for incident in classification_patterns.get('true_positive_incidents', [])):
                        tp_count += 1
                    
                    # Check in FP incidents
                    elif any(incident.get('IncidentId', '') == incident_id or 
                             incident.get('id', '') == incident_id or
                             incident.get('IncidentName', '') == incident_id 
                             for incident in classification_patterns.get('false_positive_incidents', [])):
                        fp_count += 1
                
                # Calculate classification ratio
                total = tp_count + fp_count
                if total > 0:
                    tp_ratio = tp_count / total
                    fp_ratio = fp_count / total
                    
                    # Add classification data to relationship
                    relationship_with_class = relationship.copy()
                    relationship_with_class['classification_data'] = {
                        'tp_count': tp_count,
                        'fp_count': fp_count,
                        'tp_ratio': tp_ratio,
                        'fp_ratio': fp_ratio,
                        'classification_confidence': max(tp_ratio, fp_ratio)
                    }
                    
                    # Add to appropriate list
                    if tp_ratio > fp_ratio:
                        tp_relationships.append(relationship_with_class)
                    else:
                        fp_relationships.append(relationship_with_class)
        
        # Sort by confidence and limit
        tp_relationships.sort(key=lambda x: x.get('classification_data', {}).get('classification_confidence', 0), reverse=True)
        fp_relationships.sort(key=lambda x: x.get('classification_data', {}).get('classification_confidence', 0), reverse=True)
        
        deduplicated_data['entity_relationships'] = {
            'true_positive': tp_relationships[:10],  # Top 10 TP relationships
            'false_positive': fp_relationships[:10]  # Top 10 FP relationships
        }
    
    return deduplicated_data

def generate_llm_friendly_summary(entity_analysis, deduplicated_data):
    """
    Generate a concise, LLM-friendly summary
    """
    summary = {
        'metadata': {
            'analyzed_incidents_count': entity_analysis.AnalyzedIncidentsCount,
            'entity_types_found': entity_analysis.EntityTypesFound,
            'high_frequency_entities_count': entity_analysis.HighFrequencyEntitiesCount,
            'generated_timestamp': datetime.now().isoformat()
        },
        'classification_patterns': {
            'true_positive': {
                'entity_patterns': {},
                'entity_relationships': []
            },
            'false_positive': {
                'entity_patterns': {},
                'entity_relationships': []
            }
        },
        'current_incident': {
            'entities': {}  # Will be populated with current incident entities
        }
    }
    
    # Add compact entity patterns by classification
    for entity_type in entity_analysis.EntityTypesFound:
        if entity_type in deduplicated_data['high_value_entities']:
            # Add TP entities
            tp_entities = deduplicated_data['high_value_entities'][entity_type]['true_positive']
            if tp_entities:
                summary['classification_patterns']['true_positive']['entity_patterns'][entity_type] = [
                    {
                        'value': e['value'],
                        'frequency': e['frequency'],
                        'subtype': e['subtype'],
                        'confidence': e.get('classification_data', {}).get('classification_confidence', 0)
                    } for e in tp_entities
                ]
            
            # Add FP entities
            fp_entities = deduplicated_data['high_value_entities'][entity_type]['false_positive']
            if fp_entities:
                summary['classification_patterns']['false_positive']['entity_patterns'][entity_type] = [
                    {
                        'value': e['value'],
                        'frequency': e['frequency'],
                        'subtype': e['subtype'],
                        'confidence': e.get('classification_data', {}).get('classification_confidence', 0)
                    } for e in fp_entities
                ]
    
    # Add entity relationships
    if 'entity_relationships' in deduplicated_data:
        # Add TP relationships
        tp_relationships = deduplicated_data['entity_relationships'].get('true_positive', [])
        for rel in tp_relationships:
            summary['classification_patterns']['true_positive']['entity_relationships'].append({
                'entity1_type': rel['entity1_type'],
                'entity1_value': rel['entity1_value'],
                'entity2_type': rel['entity2_type'],
                'entity2_value': rel['entity2_value'],
                'co_occurrence': rel['co_occurrence'],
                'confidence': rel.get('classification_data', {}).get('classification_confidence', 0)
            })
        
        # Add FP relationships
        fp_relationships = deduplicated_data['entity_relationships'].get('false_positive', [])
        for rel in fp_relationships:
            summary['classification_patterns']['false_positive']['entity_relationships'].append({
                'entity1_type': rel['entity1_type'],
                'entity1_value': rel['entity1_value'],
                'entity2_type': rel['entity2_type'],
                'entity2_value': rel['entity2_value'],
                'co_occurrence': rel['co_occurrence'],
                'confidence': rel.get('classification_data', {}).get('classification_confidence', 0)
            })
    
    return summary

def extract_current_incident_entities(base_object):
    """Extract entities from the current incident"""
    current_entities = {}
    
    # Extract Account entities
    if hasattr(base_object, 'Accounts') and base_object.Accounts:
        current_entities['Account'] = []
        for account in base_object.Accounts:
            current_entities['Account'].append({
                'value': account.get('userPrincipalName', ''),
                'subtype': 'UPN'
            })
    
    # Extract IP entities
    if hasattr(base_object, 'IPs') and base_object.IPs:
        current_entities['IP'] = []
        for ip in base_object.IPs:
            current_entities['IP'].append({
                'value': ip.get('Address', ''),
                'subtype': 'Address'
            })
    
    # Extract Host entities
    if hasattr(base_object, 'Hosts') and base_object.Hosts:
        current_entities['Host'] = []
        for host in base_object.Hosts:
            current_entities['Host'].append({
                'value': host.get('HostName', ''),
                'subtype': 'Hostname'
            })
    
    # Extract Domain entities
    if hasattr(base_object, 'Domains') and base_object.Domains:
        current_entities['Domain'] = []
        for domain in base_object.Domains:
            current_entities['Domain'].append({
                'value': domain.get('Domain', ''),
                'subtype': 'Domain'
            })
    
    # Extract Email entities from OtherEntities if present
    if hasattr(base_object, 'OtherEntities') and base_object.OtherEntities:
        current_entities['Email'] = []
        for entity in base_object.OtherEntities:
            raw_entity = entity.get('RawEntity', {})
            if any(email_prop in raw_entity for email_prop in 
                  ['recipient', 'p1Sender', 'p2Sender', 'networkMessageId', 'subject']):
                
                # Extract email properties
                if 'p1Sender' in raw_entity and raw_entity['p1Sender']:
                    current_entities['Email'].append({
                        'value': raw_entity['p1Sender'],
                        'subtype': 'Sender'
                    })
                
                if 'recipient' in raw_entity and raw_entity['recipient']:
                    current_entities['Email'].append({
                        'value': raw_entity['recipient'],
                        'subtype': 'Recipient'
                    })
                
                if 'senderIP' in raw_entity and raw_entity['senderIP']:
                    current_entities['Email'].append({
                        'value': raw_entity['senderIP'],
                        'subtype': 'SenderIP'
                    })
    
    # Extract File entities
    if hasattr(base_object, 'Files') and base_object.Files:
        current_entities['File'] = []
        for file in base_object.Files:
            current_entities['File'].append({
                'value': file.get('FileName', ''),
                'subtype': 'FileName'
            })
    
    # Extract FileHash entities
    if hasattr(base_object, 'FileHashes') and base_object.FileHashes:
        current_entities['FileHash'] = []
        for file_hash in base_object.FileHashes:
            current_entities['FileHash'].append({
                'value': file_hash.get('FileHash', ''),
                'subtype': file_hash.get('Algorithm', 'Unknown')
            })
    
    # Extract URL entities
    if hasattr(base_object, 'URLs') and base_object.URLs:
        current_entities['URL'] = []
        for url in base_object.URLs:
            current_entities['URL'].append({
                'value': url.get('Url', ''),
                'subtype': 'URL'
            })
    
    return current_entities

def add_email_analysis_to_comment(entity_analysis, comment):
    """
    Add email-specific analysis to the incident comment
    """
    # Check if we have any email entities
    email_entities = entity_analysis.EntitiesByType.get('Email', [])
    if not email_entities:
        return comment
    
    # Add email analysis section
    comment += "<h4>Email Analysis</h4>"
    
    # Analyze email senders
    senders = [e for e in email_entities if e['subtype'] == 'Sender']
    if senders:
        senders.sort(key=lambda x: x['frequency'], reverse=True)
        sender_data = []
        for sender in senders[:10]:
            sender_data.append({
                'Sender': sender['value'],
                'Frequency': sender['frequency'],
                'Incidents': ', '.join(map(str, sender['incidents']))
            })
        
        comment += "<h5>Common Email Senders</h5>"
        comment += data.list_to_html_table(sender_data, max_rows=10, index=False)
    
    # Analyze email domains
    domains = [e for e in email_entities if e['subtype'] == 'SenderDomain']
    if domains:
        domains.sort(key=lambda x: x['frequency'], reverse=True)
        domain_data = []
        for domain in domains[:10]:
            domain_data.append({
                'Domain': domain['value'],
                'Frequency': domain['frequency'],
                'Incidents': ', '.join(map(str, domain['incidents']))
            })
        
        comment += "<h5>Common Sender Domains</h5>"
        comment += data.list_to_html_table(domain_data, max_rows=10, index=False)
    
    # Analyze email subjects
    subjects = [e for e in email_entities if e['subtype'] == 'Subject']
    if subjects:
        subjects.sort(key=lambda x: x['frequency'], reverse=True)
        subject_data = []
        for subject in subjects[:10]:
            subject_data.append({
                'Subject': subject['value'],
                'Frequency': subject['frequency'],
                'Incidents': ', '.join(map(str, subject['incidents']))
            })
        
        comment += "<h5>Common Email Subjects</h5>"
        comment += data.list_to_html_table(subject_data, max_rows=10, index=False)
    
    return comment

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
    
    # Add email-specific analysis
    comment = add_email_analysis_to_comment(entity_analysis, comment)
    
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