import logging
import traceback as tb
import json
import azure.functions as func
from classes import STATError
from shared import coordinator, data

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    logging.debug('STAT Function started processing a request.')
    logging.info(f"Route params: {req.route_params}")
    module_name = req.route_params.get('modulename')
    logging.info(f"Module name received: '{module_name}'")
    
    try:
        req_body = req.get_json()
    except ValueError:
        logging.error(msg={'Error': 'Invalid Request Body', 'InvocationId': context.invocation_id})
        return func.HttpResponse(json.dumps({'Error': 'Invalid Request Body', 'InvocationId': context.invocation_id}), status_code=400, mimetype='application/json')

    try:
        return_data = coordinator.initiate_module(module_name=module_name, req_body=req_body)
    except STATError as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(msg={'Error': e.error, 'SourceError': e.source_error, 'InvocationId': context.invocation_id}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': e.error, 'InvocationId': context.invocation_id, 'SourceError': e.source_error, 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=e.status_code, mimetype='application/json')
    except Exception as e:
        trace = tb.format_exception(None, e, e.__traceback__)
        logging.error(e, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id, 'STATVersion': data.get_current_version(), 'Traceback': trace}), status_code=400, mimetype='application/json')
    except:
        logging.error(msg={'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id}, exc_info=True)
        return func.HttpResponse(json.dumps({'Error': 'Module processing failed, an unknown exception has occurred.', 'InvocationId': context.invocation_id, 'STATVersion': data.get_current_version()}), status_code=400, mimetype='application/json')
    
    return func.HttpResponse(body=json.dumps(return_data.body.__dict__), status_code=return_data.statuscode, mimetype=return_data.contenttype)
