from classes import BaseModule, Response, EntityAnalysisModule, STATError
from shared import rest, data
import json
import logging

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
    
    # Load data from the similar incidents module
    similar_incidents_data = req_body.get('SimilarIncidentsData', {})
    if not similar_incidents_data:
        raise STATError('No similar incidents data provided for entity analysis', {}, 400)
    
    detailed_results = similar_incidents_data.get('DetailedResults', [])
    entity_analysis.AnalyzedIncidentsCount = len(detailed_results)
    
    if entity_analysis.AnalyzedIncidentsCount == 0:
        return Response(entity_analysis)
    
    # Process and analyze entities from incidents
    extract_entities_from_incidents(base_object, entity_analysis, detailed_results)
    
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
            req_body.get('IncidentTaskInstructions')
        )
    
    return Response(entity_analysis)

def extract_entities_from_incidents(base_object, entity_analysis, incidents):
    """
    Extract entities from each incident and organize them by type
    """
    # Initialize entity tracking structures
    for entity_type in entity_analysis.EntityTypes:
        entity_analysis.EntitiesByType[entity_type] = []
    
    entity_analysis.EntityTypesFound = []
    all_entities_count = 0
    
    # Process each incident to extract entities
    for incident in incidents:
        incident_id = incident.get('IncidentNumber')
        incident_arm_id = get_incident_arm_id(base_object, incident)
        
        if not incident_arm_id:
            continue
        
        # Query incident entities
        try:
            incident_entities = get_incident_entities(base_object, incident_arm_id)
            process_incident_entities(entity_analysis, incident_entities, incident_id)
            all_entities_count += len(incident_entities)
        except Exception as e:
            logging.warning(f"Failed to extract entities from incident {incident_id}: {str(e)}")
    
    entity_analysis.AnalyzedEntitiesCount = all_entities_count
    
    # Determine which entity types were found
    for entity_type in entity_analysis.EntityTypes:
        if entity_analysis.EntitiesByType.get(entity_type) and len(entity_analysis.EntitiesByType[entity_type]) > 0:
            entity_analysis.EntityTypesFound.append(entity_type)

def get_incident_arm_id(base_object, incident):
    """
    Get the ARM ID for an incident to query its entities
    """
    incident_id = incident.get('IncidentNumber')
    incident_url = incident.get('IncidentUrl', '')
    
    # Try to extract from URL
    if incident_url and '/incident/' in incident_url:
        try:
            parts = incident_url.split('/incident/')
            if len(parts) > 1:
                arm_id_parts = parts[1].split('?')[0].split('/')
                # Format varies depending on portal URL structure
                # This is a simplified approach - may need adjustment for actual URL format
                arm_components = [
                    "subscriptions", arm_id_parts[0],
                    "resourceGroups", base_object.SentinelRGName,
                    "providers", "Microsoft.OperationalInsights",
                    "workspaces", base_object.WorkspaceName,
                    "providers", "Microsoft.SecurityInsights",
                    "incidents", arm_id_parts[-1]
                ]
                return "/" + "/".join(arm_components)
        except:
            pass
    
    # If URL extraction failed, try to get from incident name
    query = f"""
    SecurityIncident
    | where IncidentNumber == {incident_id}
    | project IncidentName
    """
    
    try:
        results = rest.execute_la_query(base_object, query, 90)
        if results and 'IncidentName' in results[0]:
            return results[0]['IncidentName']
    except:
        pass
    
    return None

def get_incident_entities(base_object, incident_arm_id):
    """
    Retrieve entities from a specific incident
    """
    # Query entities for this incident
    path = f"{incident_arm_id}/entities?api-version=2023-02-01"
    
    try:
        response = rest.rest_call_get(base_object, 'arm', path)
        entities_data = json.loads(response.content)
        return entities_data.get('value', [])
    except Exception as e:
        logging.warning(f"Error retrieving entities: {str(e)}")
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
    file_name = properties.get('friendlyName', '')
    
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