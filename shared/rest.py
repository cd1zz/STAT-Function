import time
import traceback
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import requests
from requests import Response, ConnectionError
import datetime as dt
import json
import os
import uuid
import time
import base64
from classes import STATError, STATNotFound, BaseModule, STATTooManyRequests
import logging

stat_token = {}
graph_endpoint = os.getenv('GRAPH_ENDPOINT')
arm_endpoint = os.getenv('ARM_ENDPOINT')
la_endpoint = os.getenv('LOGANALYTICS_ENDPOINT')
m365_endpoint = os.getenv('M365_ENDPOINT')
mde_endpoint = os.getenv('MDE_ENDPOINT')
default_tenant_id = os.getenv('AZURE_TENANT_ID')
mdca_endpoint = os.getenv('MDCA_ENDPOINT')
kv_endpoint = os.getenv('KEYVAULT_ENDPOINT')
kv_secret_name = os.getenv('KEYVAULT_SECRET_NAME')
kv_client_id = os.getenv('KEYVAULT_CLIENT_ID')
kv_secret = None

def token_cache(base_module:BaseModule, api:str):
    global stat_token

    default_tenant = os.getenv('AZURE_TENANT_ID')

    match api:
        case 'arm':
            tenant = base_module.MultiTenantConfig.get('ARMTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('armtoken'), tenant)
            return stat_token[tenant]['armtoken']
        case 'msgraph':
            tenant = base_module.MultiTenantConfig.get('MSGraphTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('msgraphtoken'), tenant) 
            return stat_token[tenant]['msgraphtoken']
        case 'la':
            tenant = base_module.MultiTenantConfig.get('LogAnalyticsTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('latoken'), tenant)
            return stat_token[tenant]['latoken']
        case 'm365':
            tenant = base_module.MultiTenantConfig.get('M365DTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('m365token'), tenant)
            return stat_token[tenant]['m365token']
        case 'mde':
            tenant = base_module.MultiTenantConfig.get('MDETenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('mdetoken'), tenant)
            return stat_token[tenant]['mdetoken']
        case 'mdca':
            tenant = base_module.MultiTenantConfig.get('M365DTenantId', base_module.MultiTenantConfig.get('TenantId', default_tenant))
            token_expiration_check(api, stat_token.get(tenant,{}).get('mdcatoken'), tenant)
            return stat_token[tenant]['mdcatoken']

def token_expiration_check(api:str, token, tenant:str):
    
    if token is None:
        acquire_token(api, tenant)
    else:
        expiration_time = dt.datetime.fromtimestamp(token.expires_on) - dt.timedelta(minutes=5)
        current_time = dt.datetime.now()

        if current_time > expiration_time:
            acquire_token(api, tenant) 

def acquire_token(api:str, tenant:str):
    global stat_token
    global kv_secret

    if kv_endpoint and kv_secret_name and kv_client_id:
        if not kv_secret:
            kv_secret = get_kv_secret()
        cred = ClientSecretCredential(tenant_id=tenant, client_id=kv_client_id, client_secret=kv_secret, additionally_allowed_tenants='*')
    else:
        cred = DefaultAzureCredential(additionally_allowed_tenants='*')

    if not stat_token.get(tenant):
        stat_token[tenant] = {}

    match api:
        case 'arm':
            stat_token[tenant]['armtoken'] = cred.get_token(get_endpoint('arm') + "/.default", tenant_id=tenant)
        case 'msgraph':
            stat_token[tenant]['msgraphtoken'] = cred.get_token(get_endpoint('msgraph') + "/.default", tenant_id=tenant)
        case 'la':
            stat_token[tenant]['latoken'] = cred.get_token(get_endpoint('la') + "/.default", tenant_id=tenant)
        case 'm365':
            stat_token[tenant]['m365token'] = cred.get_token(get_endpoint('m365') + "/.default", tenant_id=tenant)
        case 'mde':
            stat_token[tenant]['mdetoken'] = cred.get_token(get_endpoint('mde') + "/.default", tenant_id=tenant)
        case 'mdca':
            stat_token[tenant]['mdcatoken'] = cred.get_token("05a65629-4c1b-48c1-a78b-804c4abdd4af/.default", tenant_id=tenant)

def get_kv_secret():
    cred = DefaultAzureCredential()
    client = SecretClient(f'https://{kv_endpoint}/', cred)
    kv_return = client.get_secret(kv_secret_name)
    return kv_return.value

def rest_call_get(base_module:BaseModule, api:str, path:str, headers:dict={}):
    '''Perform a GET HTTP call to a REST API.  Accepted API values are arm, msgraph, la, m365 and mde'''

    response = execute_rest_call(base_module, 'get', api, path, None, headers)
    
    return response

def rest_call_post(base_module:BaseModule, api:str, path:str, body, headers:dict={}):
    '''Perform a POST HTTP call to a REST API.  Accepted API values are arm, msgraph, la, m365 and mde'''

    response = execute_rest_call(base_module, 'post', api, path, body, headers)
    
    return response

def rest_call_put(base_module:BaseModule, api:str, path:str, body, headers:dict={}):
    '''Perform a PUT HTTP call to a REST API.  Accepted API values are arm, msgraph, la, m365 and mde'''
    
    response = execute_rest_call(base_module, 'put', api, path, body, headers)
    
    return response

def execute_rest_call(base_module:BaseModule, method:str, api:str, path:str, body=None, headers:dict={}):
    token = token_cache(base_module, api)
    url = get_endpoint(api) + path
    headers['Authorization'] = 'Bearer ' + token.token

    retry_call = True
    wait_time = 0

    while retry_call:
        try:
            match method:
                case 'get':
                    response = requests.get(url=url, headers=headers)
                case 'post':
                    response = requests.post(url=url, json=body, headers=headers)
                case 'put':
                    response = requests.put(url=url, json=body, headers=headers)
                case _:
                    raise STATError(error=f'Invalid rest method: {method}.', status_code=400)
            check_rest_response(response, api, path)
        except STATTooManyRequests as e:
            wait_time += int(e.retry_after)
            if wait_time >= 40:
                raise STATTooManyRequests(error=e.error, source_error=e.source_error, status_code=429, retry_after=e.retry_after)
            time.sleep(int(e.retry_after))
        except ConnectionError as e:
            wait_time += 20
            if wait_time >= 40:
                raise STATError(error=f'Failed to establish a new connection to {url}', source_error=e, status_code=500)
            time.sleep(20)
        else:
            retry_call = False
    
    return response
   

def check_rest_response(response:Response, api, path):
    if response.status_code == 404:
        raise STATNotFound(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    elif response.status_code == 429:
        raise STATTooManyRequests(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)}, retry_after=response.headers.get('Retry-After'), status_code=429)
    elif response.status_code >= 300:
        raise STATError(f'The API call to {api} with path {path} failed with status {response.status_code}', source_error={'status_code': int(response.status_code), 'reason': str(response.reason)})
    return

def execute_la_query(base_module:BaseModule, query:str, lookbackindays:int, endpoint:str='query'):
    duration = 'P' + str(lookbackindays) + 'D'

    if endpoint == 'search':
        path = '/v1/workspaces/' + base_module.WorkspaceId + f'/search?timespan={duration}'
        body = {'query': query}
    else:
        path = '/v1/workspaces/' + base_module.WorkspaceId + '/query'
        body = {'query': query, 'timespan': duration}
    
    response = rest_call_post(base_module, 'la', path, body)
    data = json.loads(response.content)
 
    columns = data['tables'][0]['columns']
    rows = data['tables'][0]['rows']
    columnlist = []
    query_results = []

    for column in columns:
        columnlist.append(column['name'])

    for row in rows:
        query_results.append(dict(zip(columnlist,row)))

    return query_results

def execute_m365d_query(base_module:BaseModule, query:str):
    path = '/api/advancedhunting/run'
    body = {'Query': query}
    response = rest_call_post(base_module, 'm365', path, body)
    data = json.loads(response.content)
    
    return data['Results']

def execute_mde_query(base_module:BaseModule, query:str):
    path = '/api/advancedqueries/run'
    body = {'Query': query}
    response = rest_call_post(base_module, 'mde', path, body)
    data = json.loads(response.content)
    
    return data['Results']

def get_endpoint(api:str):
    try:
        match api:
            case 'arm':
                return 'https://' + arm_endpoint
            case 'msgraph':
                return 'https://' + graph_endpoint
            case 'la':
                return 'https://' + la_endpoint
            case 'm365':
                return 'https://' + m365_endpoint
            case 'mde':
                return 'https://' + mde_endpoint
            case 'mdca':
                return 'https://' + mdca_endpoint
    except TypeError:
        raise STATError(f'The STAT Function Application Setting was not configured for the {api} API. '
                        'Ensure that all API endpoint enrivonrment variables are correctly set in the STAT Function App '
                        '(ARM_ENDPOINT, GRAPH_ENDPOINT, LOGANALYTICS_ENDPOINT, M365_ENDPOINT, MDE_ENDPOINT, and MDCA_ENDPOINT).')
    
def add_incident_comment(base_module:BaseModule, comment:str):
    path = base_module.IncidentARMId + '/comments/' + str(uuid.uuid4()) + '?api-version=2023-02-01'
    try:
        response = rest_call_put(base_module, 'arm', path, {'properties': {'message': comment[:30000]}})
    except:
        response = 'Comment failed'
    return response

def add_incident_task(base_module:BaseModule, title:str, description:str, status:str='New'):
    path = base_module.IncidentARMId + '/tasks/' + str(uuid.uuid4()) + '?api-version=2024-03-01'

    if description is None or description == '':
        try:
            response = rest_call_put(base_module, 'arm', path, {'properties': {'title': title, 'status': status}})
        except:
            response = 'Task addition failed'
    else:
        try:
            response = rest_call_put(base_module, 'arm', path, {'properties': {'title': title, 'description': description[:3000], 'status': status}})
        except:
            response = 'Task addition failed'
    return response

def check_app_role(base_module:BaseModule, token_type:str, app_roles:list):
    token = token_cache(base_module, token_type)

    content = token.token.split('.')[1] + '=='
    b64_decoded = base64.urlsafe_b64decode(content)
    decoded_token = json.loads(b64_decoded) 
    token_roles = decoded_token.get('roles')

    matched_roles = [item for item in app_roles if item in token_roles]
    if matched_roles:
        return True
    return False

def get_incident_entities(base_object:BaseModule, incident_id, max_retries=3, retry_delay=5, api_version='2025-03-01'):
    """
    Get entities for a specific incident.
    
    Args:
        base_object: The BaseModule object containing connection information
        incident_id: The ID of the incident to retrieve entities for
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        api_version: API version to use for the request
    
    Returns:
        List of entity objects or empty list if failed
    """
    logging.info(f"Getting entities for incident: {incident_id}")
    
    # Construct the path based on the incident ID format
    try:
        # Full ARM ID format
        if incident_id.startswith('/subscriptions/'):
            path = f"{incident_id}/entities?api-version={api_version}"
        # GUID only format
        elif base_object.IncidentARMId:
            base_path = '/'.join(base_object.IncidentARMId.split('/')[:-1])
            path = f"{base_path}/{incident_id}/entities?api-version={api_version}"
        else:
            logging.error(f"Cannot construct entity path: incident_id={incident_id}, IncidentARMId={base_object.IncidentARMId}")
            return []
        
        logging.info(f"Using API path: {path}")
        
        # Retry loop for the API call
        for attempt in range(max_retries):
            try:
                # Use POST with empty body per the API documentation
                response = rest_call_post(base_object, 'arm', path, {})
                
                if response.status_code == 200:
                    content = json.loads(response.content)
                    
                    if 'value' in content:
                        entities = content['value']
                        logging.info(f"Retrieved {len(entities)} entities for incident {incident_id}")
                        return entities
                    else:
                        logging.warning(f"Response missing 'value' key for incident {incident_id}")
                
                # Retry logic
                if attempt < max_retries - 1:
                    logging.info(f"Retrying API call after {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
            
            except Exception as e:
                if attempt < max_retries - 1:
                    logging.warning(f"Error getting entities, retrying: {str(e)}")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"All retry attempts failed for incident {incident_id}")
                    logging.error(traceback.format_exc())
    
    except Exception as e:
        logging.error(f"Failed to process incident {incident_id}: {str(e)}")
        logging.error(traceback.format_exc())
    
    return []