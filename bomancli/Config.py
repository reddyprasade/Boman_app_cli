import docker
import os 

class Config:

    #boman_url
    try:
        docker_client = docker.from_env()
    except Exception as e:
        print('Docker not found in your machine, Pls install')
        #print(str(e))
        exit(3) ## docker/system error

    boman_url = "https://dashboard.boman.ai/v2/"  ## boman server ip // https://dashboard.boman.ai http://192.168.1.6:3000

    sast_present = None
    sast_lang = None
    sast_target = None
    #sast_env = None ## for snyk

   
    sast_scan_status = None
    sast_upload_status = None
    sast_message = None
    sast_errors = None

    dast_present = None
    dast_target = None
    dast_type = None
    dast_api_type = None

    dast_scan_status = None
    dast_upload_status = None
    dast_message = None
    dast_errors = None


#    zap_context_configured = None
 #   zap_context_file_nmae = None
  #  zap_context_cmd = None
   # zap_hook_file_name = None
    


    dast_cred_present = None
    dast_username = None
    dast_password = None
    
    sca_present = None
    sca_lang = None
    
    sca_scan_status = None
    sca_upload_status = None
    sca_message = None
    sca_errors = None

    app_token = None
    customer_token = None


    sast_build_dir = None
    sca_build_dir = None


    secret_scan_present = None

    build_dir = None 

    dast_response = None
    sast_response = None
    sca_response = None
    secret_scan_response = None

    secret_scan_message = None
    secret_scan_status = None
    secret_scan_upload_status = None
    secret_scan_errors = None


    app_loc = 0
    
    scan_token = None
    scan_name = 'NA'


    log_level = "INFO"

    version = 'v1.03'
