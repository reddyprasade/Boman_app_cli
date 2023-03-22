import requests
# from base_logger import logging
# from Config import Config
from bomancli.base_logger import logging
from bomancli.Config import Config

import json 



## function to authorize and get the images form SAAS --------------------------------------------------------
def authorize():
    logging.info('Authenticating with boman server')
    url = Config.boman_url+"/api/app/authorize"
    data = {'app_token': Config.app_token, 'customer_token': Config.customer_token, 'sast':Config.sast_present,"dast":Config.dast_present,"dast_type":Config.dast_type,"sast_langs":Config.sast_lang,"sca":Config.sca_present,"sca_langs":Config.sca_lang,"secret_scan":Config.secret_scan_present}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    try:
        res = requests.post(url, json=data, headers=headers)
        #print('req:', json.dumps(data))
        #print('res:',json.loads(res.content))
    except requests.ConnectionError:
       logging.error("Can't connect to the Server while authorizing, Please check your Internet connection.")
       exit(1) #server/saas error
    else:
        if res.status_code == 200:
            try:
                json_response = json.loads(res.content)
                logging.info('Authentication Done')
            except:
                logging.info('Authentication Failure')
            try:
                Config.dast_response = json_response['data']['dast']
                Config.sast_response = json_response['data']['sast']
                Config.sca_response = json_response['data']['sca']
                Config.secret_scan_response = json_response['data']['secret_scan']
                Config.scan_token = json_response['data']['scan_token']    
                Config.scan_name = json_response['data']['scan_name']    

                return 1    
            except:
                logging.error('Problem when authenticating with server, Check with boman.ai team id scan doesnt completed')  
                exit(1) ## server error  
                    

        elif res.status_code == 401:
            logging.error('Unauthorized Access. Check the tokens')	
    exit(2) ##auth error
