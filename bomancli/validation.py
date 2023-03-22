# from base_logger import logging
# from Config import Config
# import utils as Utils

from bomancli import utils as Utils
from bomancli.base_logger import logging
from bomancli.Config import Config


import yaml
import json
import requests
import os


#### read the input from the yaml file -- MM ------------------------------------------------------------

def yamlValidation():

    logging.info('Finding boman.yaml file')

    try: 
        with open('boman.yaml', 'r') as file:
            Config.config_data = yaml.safe_load(file)    
        logging.info('Config yaml file found')    
    except:
        
        logging.error('No config yaml file found')
        exit(4) ## validation error 

    logging.info('Prasing and Validating the config yaml file')
   


    try:
        Config.config_data['Auth']
        if Config.config_data['Auth'] != '':
            Config.app_token = Config.config_data['Auth']['project_token']
            Config.customer_token =Config.config_data['Auth']['customer_token']


    except KeyError:

        logging.error('Project and Customer token is mandatory to run the scan. Refer the documentation.')    


    try: 

        if  Config.config_data['SAST'] != '':
            Config.sast_lang = Config.config_data['SAST']['language'].split(",") ## comma sperated if mulitple
            
            Config.sast_present = True
            Config.sast_message = 'SAST is properly configured'
            logging.info('SAST is properly configured with %s and ready to scan',Config.sast_lang)

            try:
                logging.info('choosing the sast working directory')
                Config.sast_build_dir  = Config.config_data['SAST']['work_dir']
            except KeyError: 
                logging.info('work dir not specified in config, choosing the default sast working directory')
                Config.sast_build_dir = os.getcwd()+'/'

            #logging.info('snyk is choosen, and the env var declared was %s', str('s'))


            



        if 'java' in Config.sast_lang:

            try:
                Config.sast_target =  Config.config_data['SAST']['target']
            except KeyError: 
                logging.error('Java requires a target file to be mentioned in the boman.yaml file. refer the documentation')
                Config.sast_present = False       
                Config.sast_message = 'SAST is not configured properly, Java requires a target file to be mentioned in the boman.yaml file. refer the documentation'    
        


        # if 'python-snyk' in Config.sast_lang:

        #         try:
        #             Config.sast_env = Config.config_data['SAST']['env']
        #             logging.info('snyk is choosen, and the env var declared was %s', str(Config.sast_env))
        #         except KeyError: 
        #             logging.error('Snyk requires a enviromenet var for snyk auth token to be mentioned in the boman.yaml file. refer the documentation')
        #             Config.sast_present = False 

        
    except KeyError:    
        Config.sast_present = False
        Config.sast_message = 'SAST was not properly defined in the config, Please check your boman.yaml file.'
        logging.warning('SAST was not properly defined in the config')
        logging.warning('Ignoring SAST, Please provide all mandatory inputs incase you like to run SAST scan.')
        

    
    ## DAST

    try: 
        Config.dast_target = Config.config_data['DAST']['URL']
        Config.dast_type = Config.config_data['DAST']['type']

        Config.dast_present = True

        try:        
            if Config.config_data['DAST']['context'] == 'true':
                Config.zap_context_configured = True
                Config.zap_context_file_nmae = Config.config_data['DAST']['context_file_name']
                Config.zap_context_cmd = Config.config_data['DAST']['context_command']
        except KeyError: 
            Config.zap_context_configured = False 


        if Utils.testDastUrl(Config.dast_target):
            logging.info('DAST is properly configured and ready to scan')
            
            if Config.dast_type == 'API':
                try:  
                    logging.info('DAST is configured for API scan, checking API type.')    
                    Config.dast_api_type = Config.config_data['DAST']['api_type']
                    
                except KeyError:
                    logging.info('DAST API type is not given, proceeding with default value: OPENAPI')
                    Config.dast_api_type = 'openapi'  


        else:    
            logging.info('DAST target is not reachable, ignoring DAST scan')
            Config.dast_present = False
            Config.dast_message = 'DAST target is not reachable. DAST scan was ignored'
                
    except KeyError:    
        Config.dast_present = False
        Config.dast_message = 'DAST was not properly defined in the config.'
        logging.warning('DAST was not properly defined in the config.')
        logging.warning('Ignoring DAST, Please provide all mandatory inputs incase you like to run DAST scan.')
        

        
               


    ## SCA

    try: 
        if  Config.config_data['SCA'] != '':
            Config.sca_lang = Config.config_data['SCA']['language'].split(",") ## comma sperated if mulitple
            
            Config.sca_present =  True

            try:
                Config.sca_build_dir = Config.config_data['SCA']['work_dir']
            except KeyError: 
                Config.sca_build_dir = os.getcwd()+'/'

            Config.sca_message ='SCA is properly configured'
            logging.info('SCA is properly configured and ready to scan')    
    except KeyError:    
        Config.sca_present =  False
        Config.sca_message ='SCA was not properly defined in the config'
        logging.warning('SCA was not properly defined in the config')
        logging.warning('Ignoring SCA, Please provide all mandatory inputs incase you like to run SCA scan.')
        
#ss
    try:
        if Config.config_data['Secret_Scan'] == False:
            Config.secret_scan_present = False
        else:   
            try:
                Config.sast_build_dir  = Config.config_data['SAST']['work_dir']
            except KeyError: 
                Config.sast_build_dir = os.getcwd()+'/'
                 
            try:
                Config.secret_scan_present =  True if Utils.isGitDirectory(Config.sast_build_dir) else False

                if Config.secret_scan_present:
                    logging.info('Secret scanning is properly configured and ready to scan')
                    Config.secret_scan_message ='Secret scanning is properly configured and ready to scan'
                else:
                    logging.warning('Secret scanning is properly configured, but working directory is not a git repository.') 
                    logging.warning('Ignoring Secret scanning.')    
                    Config.secret_scan_message ='Secret scanning is properly configured, but working directory is not a git repository.'       
            except KeyError:
                Config.secret_scan_present = False
                logging.warning('Secret scanning is not properly configured, Working directory is not git.') 
                Config.secret_scan_message ='Secret scanning is not properly configured'     
    except KeyError:
        Config.secret_scan_present = False  
        logging.warning('Secret scanning is not properly configured. Cant read the Secret_Scan configuration.')   
        Config.secret_scan_message ='Secret scanning is not properly configured'  


        

    

## need to use lingudetect here, but the results are not trustable and misleading ------ MM -------------------
def findLang():
    print('[INFO]: Detecting Language')
