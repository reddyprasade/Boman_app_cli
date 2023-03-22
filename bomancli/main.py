## importing required libraries

#import docker
import yaml
import json
import time
import os
import requests
import argparse
import subprocess
from pathlib import Path
import sys

##importing required files

#import linguDetect/lingu_detect as ling
# from base_logger import logging
# from Config import Config

# import validation as Validation
# import utils as Utils
# import auth as Auth

from docker import errors
from bomancli.base_logger import logging
from bomancli.Config import Config

from bomancli import validation as Validation
from bomancli import utils as Utils
from bomancli import auth as Auth


parser = argparse.ArgumentParser(
	prog='bomancli',
	description='''
	#This is a CLI tool to communicate with Boman.ai server
	''',
	epilog='copyright (c) 2022 SUMERU'
	)


docker = Config.docker_client

### function to init the scan and will check the docker is in place
def init():

    print('New Scan has been Initiated')
    logging.info('Checking for Docker in the Env')
    try:
        #docker = docker.from_env()
        if docker.ping():
           logging.info('Docker is running in the Environment')
        else:
            logging.error('Unable to connect to docker, Please install docker in your environment')
    except Exception as e:
        logging.error('Docker not found in your machine, Pls install')
        #print(str(e))
        exit(3) ## docker/system error




### Run the scanners -- MM
### function to run the image -- MM ---------------------------------------------------------------------------

def runImage(data=None,type=None):

    if data is None:
        logging.error('Unable to access the response data while running the scan')

    if type is None:
        logging.error('Unable to access the response data while running the scan')



    #print(data['image'])
    docker_image = data['image']
    #lang= None
    tool_name =data['tool']
    command_line= data['command']
    output_file= data['output_file']
    will_generate_output = data['will_generate_output']
    tool_id= data['tool_id']
    scan_details_id= data['scan_details_id']
    conversion_required = data['conversion_required']
   

    #print(docker_image,tool_name,command_line,output_file,will_generate_output,tool_id,scan_details_id)

    if docker_image is None:
        print('Problem with running the scanner, image not specified.')
        exit('3') ## docker/system error

    try:

        uid = os.getuid()
        gid = os.getgid()


        userid= f"{uid}:{gid}"
    except:
        userid= 'root'

    logging.info('Running all the scans/docker with the user %s',userid)


    try:
        logging.info('environment var configured for the scan is not picked up by the cli ')
        #raw_env = 'SNYK_TOKEN=3884117f-5c4f-45e4-a171-ec8e71470203,test=test'
        env = data['env']
        env_var =  env.split(',')
        logging.info('environment var configured for the scan is %s',str(env_var))
    except:
        env_var = ['test=test']
        logging.info('environment var configuration failed or cant find the variables from sass')



    if type == 'SAST':
        target_file = Config.sast_target
        Utils.checkImageAlreadyExsist(docker_image)

        logging.info('Running %s in the repository',tool_name)

        if data['dynamic_comment'] == 1:
            command_line = "% s" % command_line.format(target_file = target_file)
            #print(Config.sast_build_dir,command_line,docker_image)
            #command_line =  repr(command_line)


        detach = True if data['detach'] == 1 else False
        container_output = None
        try:

            if tool_name == 'Codeql':


                logging.info('processing commands for the codeql')

                codeql_command = command_line.split(',')

                logging.info('Building the project using codeql')

                try:
                    Config.build_dir = Config.sast_build_dir
                    container_output = docker.containers.run(docker_image, codeql_command[0], volumes={Config.sast_build_dir: {
                            'bind': data['bind']}}, user=userid,detach=detach,environment=env_var)
                    logging.info('[SUCCESS]: %s buidling completed',tool_name)

                except errors.ContainerError as exc:
                    msg='\n The following error has been recorded while building project'
                    Utils.logError(msg,str(exc))
                    Utils.logError('details',str(container_output))
                    Config.sast_scan_status = 'Completed'
                    Config.sast_errors = 'Unrecongnized error recorded while builiding, [message from tool',str(exc),']'
                    logging.error('%s',str(exc))
                    logging.error('%s',str(container_output))



                logging.info('Analyzing/scanning the project using codeql')

                try:
                    Config.build_dir = Config.sast_build_dir
                    container_output = docker.containers.run(docker_image, codeql_command[1], volumes={Config.sast_build_dir: {
                            'bind': data['bind']}}, user=userid,detach=detach,environment=env_var)
                    logging.info('[SUCCESS]: %s Analyzing completed',tool_name)

                except errors.ContainerError as exc:
                    msg='\n The following error has been recorded while analyzing project'
                    Utils.logError(msg,str(exc))
                    Config.sast_scan_status = 'Completed'
                    Config.sast_errors = 'Unrecongnized error recorded while analyzing, [message from tool',str(exc),']'
                    logging.error('%s',str(exc))

                
            else:
                Config.build_dir = Config.sast_build_dir
                container_output = docker.containers.run(docker_image, command_line, volumes={Config.sast_build_dir: {
                            'bind': data['bind']}}, user=userid,detach=detach,environment=env_var)
                logging.info('[SUCCESS]: %s Scan Completed',tool_name)

            




        except errors.ContainerError as exc:
            msg='\n The following error has been recorded while scanning SAST'
            Utils.logError(msg,str(exc))
            logging.error('[WARNING]: Some Error recorded while scanning %s',tool_name)
            Config.sast_scan_status = 'Completed'
            Config.sast_errors = 'Unrecongnized error recorded while scanning, [message from tool',str(exc),']'
            logging.error('%s',str(exc))



        try:

            if will_generate_output == 1:
                #logging.info('WILL GENERATE OUTPUT')
                if uploadReport(output_file,tool_name,tool_id,scan_details_id,'SAST'):
                    Config.sast_scan_status = 'Completed'
                    Config.sast_upload_status ='Completed'
                    Config.sast_message = 'Scan is completed'
                else:
                    Config.sast_upload_status ='Failed'
                    Config.sast_message ='Error occured while uploading the report, Please check the cli logs'
            else:

                ## incase file type is other than json
                if conversion_required == 1:
                    if tool_name == 'Findsecbugs':
                        logging.info('Converting the findsec results to consumable format')

                        if Utils.convertXmlToJson('boman_findsecbug.xml',Config.sast_build_dir,'boman_findsecbug.json'):
                            logging.info('Conversion done')
                        else:
                            logging.error('Conversion Failed, Please contact admin.')
                            Config.sast_message = 'Findsecbugs report to boman conversion Failed'
                            return 0
                        if uploadReport(output_file,tool_name,tool_id,scan_details_id,'SAST'):
                            Config.sast_scan_status = 'Completed'
                            Config.sast_upload_status ='Completed'
                            Config.sast_message = 'Scan is completed'
                        else:
                            Config.sast_upload_status ='Failed'
                            Config.sast_message ='Error occured while uploading the report, Please check the cli logs'
                else:
                ## incase of json
                    with open(Config.sast_build_dir+output_file, 'w', encoding='utf-8') as f:
                        json.dump(json.loads(container_output), f, ensure_ascii=False, indent=4)
                        Config.sast_scan_status = 'Completed'

                    if uploadReport(output_file,tool_name,tool_id,scan_details_id,'SAST'):
                        Config.sast_scan_status = 'Completed'
                        Config.sast_upload_status ='Completed'
                        Config.sast_message = 'Scan is completed'
                    else:
                        Config.sast_upload_status ='Failed'
                        Config.sast_message ='Error occured while uploading the report, Please check the cli logs'    

        except EnvironmentError as e:
            logging.error('%s',str(e))
            Config.sast_message = 'Error while uploading the report',tool_name,' [',str(e),']'
            logging.WARNING('Error while uploading the report of %s',tool_name)
            msg='Error while uploading the report'
            Utils.logError(msg,e)

    if type == 'DAST':

        Utils.checkImageAlreadyExsist(docker_image)
        logging.info('Running %s on %s ',tool_name, Config.dast_target)
        #command_line = '-h '+Config.dast_target+' -maxtime 10 -o tmp/'+output_file
        #print(command_line_nikto)
        detach = True if data['detach'] == 1 else False

        if Config.sast_build_dir == None:
            Config.sast_build_dir = os.getcwd()+'/'

        if data['dynamic_comment'] == 1:
            target_url = Config.dast_target

            if Config.dast_type == "API":
                api_type = Config.dast_api_type
                command_line = "% s" % command_line.format(target_url = target_url, api_type=api_type)
            else:
                command_line = "% s" % command_line.format(target_url = target_url)

            #print(command_line)


            ## context file appending -- MM

   #         if Config.zap_context_configured == 'true':

    #            context_file_name = Config.zap_context_file_nmae
     #           context_command = Config.zap_context_cmd
      #          command_line = "% s" % command_line.format(context_file = context_file_name)



        try:
            Config.build_dir = Config.sast_build_dir
            container= docker.containers.run(docker_image, command_line, volumes={Config.sast_build_dir: {
 			 	'bind': data['bind'], 'mode': 'rw'}},user=userid,detach=detach)

            #print(output_file,toolname,tool_id,scan_details_id)
            logging.info('[SUCCESS]: %s Scan Completed',tool_name)
            Config.dast_scan_status ='Completed'
        except errors.ContainerError as exc:
            Config.dast_scan_status ='Completed'
            logging.error('[ERROR]: Error recorded while Scanning %s',tool_name)
            Config.dast_errors = 'Error recorded while Scanning',tool_name, '[',str(exc),']'
            msg='\n The following error has been recorded while scanning DAST'
            Utils.logError(msg,str(exc))



        try:
            if will_generate_output == 1:
                logging.info('Uploading %s to the server',output_file)
                if uploadReport(output_file,tool_name,tool_id,scan_details_id,'DAST'):
                    Config.dast_scan_status = 'Completed'
                    Config.dast_upload_status ='Completed'
                    Config.dast_message = 'Scan is completed'
                else:
                    Config.dast_upload_status ='Failed'
                    Config.dast_message ='Error occured while uploading the report, Please check the cli logs'
            else:
                logging.error('Cant upload files to the server %s',tool_name)
                Config.dast_message ='Cant upload files to the server',tool_name

        except:
            logging.error('Error recorded while uploading the report %s',tool_name)
            Config.dast_message ='Error recorded while uploading the report of',tool_name

    if type == 'SCA':
        Utils.checkImageAlreadyExsist(docker_image)
        logging.info('Running %s',tool_name)
        try:
            Config.build_dir = Config.sca_build_dir
            container_output = docker.containers.run(docker_image, command_line, volumes={Config.sca_build_dir: {
                     'bind': data['bind']}}, user=uid)
            logging.info('[SUCCESS]: %s Scan Completed',tool_name)
            Config.sca_message ='SCA scan completed'
            Config.sca_scan_status ='Completed'
        except errors.ContainerError as exc:
           logging.error('Some Error recorded while scanning %s',tool_name)
           logging.error('%s',str(exc))
           msg='\n The following error has been recorded while scanning sca'
           Config.sca_scan_status ='Completed'
           Config.sca_errors ='Some Error recorded while scanning [',str(exc),']'
           Utils.logError(msg,str(exc))

        try:
            if will_generate_output == 1:
                logging.info('Uploading %s to the server',output_file)
                if uploadReport(output_file,tool_name,tool_id,scan_details_id,'SCA'):
                    Config.sca_scan_status ='Completed'
                    Config.sca_upload_status = 'Completed'
                    Config.sca_message ='Scan Completed'
                else:
                    Config.sca_scan_status ='Failed'
                    Config.sca_upload_status = 'Failed'
                    Config.sca_message ='Error occured while uploading the report, Please check the cli logs'
            else:
                logging.error('Cant upload files to the server',tool_name)
                Config.sca_message ='Cant upload files to the server for SCA,Please check your directory for the files.'

        except EnvironmentError as e:
            logging.error('Error recorded while uploading the report %s',tool_name)
            logging.error('%s',str(e))
            Config.sca_message ='Error recorded while uploading the report of SCA, Please check your directory for the files.'           ## need to change logic here -- MM
            msg = 'Error recorded while uploading the report'
            Utils.logError(msg,str(e))



#### function to upload the test report to the server with other data -- MM ------------------------------------
def uploadReport(filename,toolname,tool_id,scan_details_id,type):

    logging.info('Uploading %s report with filename: %s', toolname,filename)
    if True:
        #build_dir = '/home/boxuser/box/trainingdata/repos/youtube-dl/'
        #print(Config.sast_build_dir+filename)
        #files = open(build_dir+filename)

        try:

            if type == 'SAST':
                message = Config.sast_message
                errors = Config.sast_error_message
            elif type == 'DAST':
                message = Config.dast_message
                errors = Config.dast_errors
            elif type == 'SCA':
                message = Config.sca_message
                errors = Config.sca_errors
            elif type =='SS':
                message = Config.secret_scan_message
                errors = Config.secret_scan_errors
        except:
            message = 'NA'
            errors = 'NA'




        try:
            logging.info('fetching the %s file from the directory %s',filename,Config.build_dir)
            ##path = '/home/boxuser/box/Vuln-code/boman_njsscan.json'


            # print(str(Config.build_dir))
            # print(str(filename))

            data_folder = Path(str(Config.build_dir))

            path = data_folder / str(filename)
           
            with open(path) as f: 
                f.seek(0)
                data = json.load(f)


        except EnvironmentError as e:
            logging.error('Error while fetching the output file from the directory')
            logging.error('%s',str(e))
            msg = 'Error while fetching the output file from the directory'
            Utils.logError(msg,str(e))
            return 0

        tool_output = json.dumps(data, ensure_ascii=False, indent=4)
    
        # files = {'upload_file': open(path,'rb')}
        
        logging.info('output size of file is %s', sys.getsizeof(tool_output))
        values = {'tool_name': toolname, 'time': time.time(),'scan_token':Config.scan_token, 'app_token':Config.app_token,'customer_token':Config.customer_token,'tool_id':tool_id,'scan_details_id':scan_details_id,"tool_results":tool_output,"message":message,"errors":errors,"app_loc":Config.app_loc}
        url = Config.boman_url+"/api/app/upload" 
        # with open(path) as f: 
        #     file_obj = f
        r = requests.post(url,json=values)
        #print(r.status_code)
        if r.status_code == 200:
            logging.info('[COMPLETED]: %s Report uploaded Successfully! Report Name: %s',toolname,filename)
            return 1
        elif r.status_code == 401 :
            logging.error('Unauthorized Access while uploading the results. Please check the app/customer tokens')
            exit(2)  ## Auth error
        else:
            logging.error('Problem While uploading the results.')
            logging.error('response code is %s',r.status_code)
            return 0
    else:
       logging.error(toolname,' Report cant be uploaded filename: %s',filename)
       return 0 ## need to write a logic here

    return 1




## function for seceert scan using trufflehog
def initSecertScan(path,data):

    build_dir = path
    command_line_truffle = data[0]['command']
    image_name= data[0]['image']
    tool_name = data[0]['tool']
    bind_dir = data[0]['bind']
    tool_id = data[0]['tool_id']
    scan_details_id = data[0]['scan_details_id']
    Utils.checkImageAlreadyExsist(image_name)


    try:
        logging.info('Running Secert Scanning on the repository')
        container = Config.docker_client.containers.run(image_name, command_line_truffle, detach=True,volumes={build_dir: {
                    'bind': bind_dir}})
        op = []
        for iteration_main,line in enumerate(container.logs(stream=True)):
            try:
                op.append(json.loads(line.strip()))
                #print(op[iteration_main]['stringsFound'])
                for iteration,key in enumerate(op[iteration_main]['stringsFound']):
                   #print(key)
                    op[iteration_main]['stringsFound'][iteration] = Utils.masker(key)

            except:
                logging.error('Some Findings from the trufflehog is unrecognisble.Skiping them.')
                Config.secret_scan_status ='Completed'
                Config.secret_scan_message ='Some Findings from the trufflehog is unrecognisble.'
                break


        logging.info('[SUCCESS]: Secert Scanning Completed ')
    except errors.ContainerError as exc:
        Config.secret_scan_errors = str(exc)
        logging.error('Error Occured while running Trufflehog on the repository')
        loggging.error('%s',str(exc))
        msg='\n The following error has been recorded while scanning Trufflehog'
        Utils.logError(msg,str(exc))

    try:
        file_name = data[0]['output_file']
        Config.build_dir = Config.sast_build_dir
        path = Config.sast_build_dir+file_name
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(op, f, ensure_ascii=False, indent=4)

        if uploadReport(file_name,tool_name,tool_id,scan_details_id,'SS'):
            logging.info('[COMPLETED]: Secert Scanning report Uploaded')
            Config.secret_scan_status ='Completed'
            Config.secret_scan_upload_status = 'Completed'
            Config.secret_scan_message = 'Scan Completed'
        else:
            logging.error('Error Occured while uploading report to boman.ai server. Please contact admin.')
    except Exception as error:
         logging.error(' Error Occured while generating report for secert scan')

    return True



#main fucntion where all the actions have been initiated
def main():



    init()
    Validation.yamlValidation()
    if Config.secret_scan_present == True or Config.sast_present is True or Config.dast_present is True or Config.sca_present is True:
        Utils.testServer()
    else:
        content = Auth.authorize()
        logging.info('Nothing configured to be scan.')
        return 0

    content = Auth.authorize()
    global scan_token

    if Config.secret_scan_present == True:

        if Utils.isGitDirectory(Config.sast_build_dir):
            logging.info('Git repository is found in the directroy')
            logging.info('Initizating Secret Scanning')
            for data in Config.secret_scan_response:
                initSecertScan(Config.sast_build_dir,data=Config.secret_scan_response)
        else:
            logging.info('Git repository not found in the directroy %s',Config.sast_build_dir)
            logging.info('Sikping secret scanning')
    else:
        logging.warning('Sikping secret scanning, since there is no git found in the directory %s',Config.sast_build_dir)


    scan_token = Config.scan_token


    if Config.sast_present is True:


        logging.info('Preparing SAST Scan')
        logging.info('Working directory is %s',Config.sast_build_dir)
        if Config.sast_lang is None:
            #findLang()
            logging.error('Language Not Defined. Exiting')
            exit(4) ## misconfig error



        sast_len = len(Config.sast_lang)

        if sast_len > 1: ## if the mentioned languages are more than one
            logging.info('Detected Languges %s',Config.sast_lang)
            for lang in Config.sast_lang:
                try:   
                    loc = Utils.getLoc(Config.sast_build_dir, lang)
                except:
                    loc = 0    
                #print(loc)
                logging.info('Running scanner with language: %s',lang)


        else:
            logging.info("Detected Language is : %s",Config.sast_lang)
            loc =  Utils.getLoc(Config.sast_build_dir, Config.sast_lang[0])
            Config.app_loc = loc
            logging.info('Loc found in the %s : %s',Config.sast_build_dir,Config.app_loc)

        for data in Config.sast_response:

            #data =  json.loads(Config.sast_response)

            if data['scan_status'] == 0 :   
                logging.info('No SAST Configuration found from SaaS')    
                logging.info('Ignoring SAST Scan')
            else:
                print(data)
                logging.info('SAST data found %s',type(data)) 
                runImage(data=data,type='SAST')

    else:
        logging.info('Ignoring SAST Scan')


    if Config.dast_present is True:
        logging.info('Preparing DAST scan')



        if Utils.testDastUrl(Config.dast_target):


           for data in Config.dast_response:

                if data['scan_status'] == 0 :   
                    logging.info('No DAST Configuration found from SaaS')    
                    logging.info('Ignoring DAST Scan')
                else:
                    runImage(data=data,type='DAST')
           # runImage(imagename= content['data']['dast']['tool_2']['image'], toolname= content['data']['dast']['tool_2']['tool'],type='DAST',output_file=content['data']['dast']['tool_2']['output_file'],tool_id=content['data']['dast']['tool_2']['tool_id'], scan_details_id=content['data']['dast']['scan_details_id'])


        else:
            logging.info('Ignoring DAST scan, since the target is unreachable')
            Config.dast_scan_status = 'Failed'
            Config.dast_upload_status ='NA'
            Config.dast_message = 'Since the target is unreachable. Scan is failed'


    else:
        logging.info('Ignoring DAST scan')


    if Config.sca_present is True:
        logging.info('Preparing SCA scan')

        
        for data in Config.sca_response:

            if data['scan_status'] == 0 :   
                logging.info('No SCA Configuration found  from SaaS')    
                logging.info('Ignoring SCA Scan')
            else:
                #print(data)
                #logging.info('SAST data found %s',type(data)) 
                runImage(data=data,type='SCA')
            
        #print('running sca')
        ##runImage(imagename= content['data']['sca']['image'], toolname= content['data']['sca']['tool'],type='SCA',output_file=content['data']['sca']['output_file'],tool_id=content['data']['sca']['tool_id'], scan_details_id=content['data']['sca']['scan_details_id'])
    else:
        logging.info('Ignoring SCA scan')



    return 1

def default():

    parser.add_argument('-a','--action',default='init',help="Action arugment, you need to pass the value for action (eg: test-saas, test-docker, run)")
    parser.add_argument('-u','--url',default='https://dashboard.boman.ai/v2/',help="Provide the URL of the boman saas (eg: Prod, On-prem)")
    parser.add_argument('-v','--version',default='show',help="will show the version of boman-cli tool",action='store_true')
    parser.add_argument('-fb','--failBuild',default='pass',help="this is the default value exit code in boman, pass fail if you want to fail the build when boman successfully runs the scan")
    #parser.add_argument('-check-docker',help='Check you docker is present in your system is compatable to run the boman.ai')
    args = parser.parse_args()

    # if len(sys.args) == 1:
    #     # display help message when no args are passed.
    #     print('Welcome to Boman CLI, pass bomancli --help to view the commands args ')
    #     exit(1)

    if args.url == 'https://dashboard.boman.ai/v2/':
        Config.boman_url = "https://dashboard.boman.ai/v2/"
    else:
        Config.boman_url = args.url   





## Action argument
    if args.action == 'init':
        print('Welcome to Boman CLI',Config.version,'pass bomancli --help to view the commands args ')
        exit(0)
    elif args.action =='run':
        logging.info("#################################### -  BOMAN Scanner Initiated - ####################################")
        if main():
            logging.info('################################ BOMAN Scanning Done ################################')
            logging.info('#####################################################################################')
            Utils.uploadLogs()
            Utils.showSummary()

            ## checking the failbuild argument
            if args.failBuild == 'fail':
                exit(-1)
            else:
                exit(0)  

            
        else:
            logging.info('All tasks done')
            exit(0)
           
    elif args.action =='test-saas':
        Utils.testServer()
        exit(0)
    elif args.action =='test-docker':
        Utils.testDockerAvailable()
        exit(0)
    elif args.action =='test-yaml':
       Validation.yamlValidation()
       exit(0)
    else:
        print('Welcome to Boman CLI',Config.version,',pass bomancli --help to view the commands args ')
        exit(0)

## version argument 
    if args.version == 'show':
        print('boman-cli '.Config.version)


## starting the cli



default()
