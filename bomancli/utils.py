
# from base_logger import logging
# from Config import Config
# import loc_finder as loc
#from datetime import datetime


from bomancli.base_logger import logging
from bomancli.Config import Config
from bomancli import loc_finder as loc


import requests


import os 
import subprocess
import json
import xmltodict
 
 
docker = Config.docker_client


##fucntion to check the docker image is already present or not
def checkImageAlreadyExsist(imagename):
    #print(imagename)
    try:
        
        image_list = docker.images.list()
        logging.info('Checking the scanner image (%s) locally',imagename)  
    except Exception as e:
        logging.error('Docker throwing a error , please check the docker installation')
        #print(str(e))
        exit(3) ## docker/system error

    for image in image_list:
       #print(image.tags)
        if imagename in image.tags:
            logging.info('Image is already in the local machine')
            return True
    
    logging.info('Image is not present in the local machine')
    logging.info('Pulling the required image [%s]',imagename)

    try:
        pulled = docker.images.pull(imagename)
        return 1
    except:
        logging.error('Error pulling the image [%s]',imagename)
        exit(3) ## docker/system error

            


### fucntion to check the git is present or not
def isGitDirectory(path):
    try:
        isdir = os.path.isdir(path+'/.git/') 
        #print(isdir) 
        return isdir
        #return subprocess.call(['git', '-C', path, 'status'], stderr=subprocess.STDOUT, stdout = open(os.devnull, 'w')) == 0
    except:
        return 0

    




### fucntion to test SaaS server, whether is up or not:
def testServer():
    logging.info('Testing Boman.ai Server')
    url = Config.boman_url+"/v1/api/app/ping"
    try:
        x = requests.get(url)  #var ="renga"
    except requests.ConnectionError as e:
        print(e)
        logging.error("Can't connect to the Server, Please check your Internet connection.")
        exit(1) #server/saas error
    else:
        if str(x.content):
            logging.info("Server is reachable ")
            return 1
        else:
            logging.error("Boman.ai Server is not reachable")	
            exit(1) ## docker/system error



### function to check docker is available in the machine or not -- MM
def testDockerAvailable():
    logging.info('Checking for docker in the machine')
    try:
        
        if docker.ping():
           logging.info('Docker is running in the machine. Good to go!')
        else:
            logging.error('Unable to connect to docker, Please install docker in your environment')    
    except Exception as e:
        logging.error('Docker not found in your machine, Please install docker to continue the scanning')
        #print(str(e))
        exit(3) ## docker/system error



### function to test the dast url is accesible or not --- MM


def testDastUrl(url):
    logging.info('Testing %s target', url)
    #url = Config.boman_url+"/api/app/ping"
    #print(url)
    try:
        x = requests.get(url)
    except requests.ConnectionError:
        logging.error("Can't connect to the %s, Please check your Internet connection.", url)
        return 0
    else:
        logging.info("DAST target is reachable")
        return 1
        # if x.status_code == 200:
           
        #     return 1
        # else:
        #     logging.error("Boman.ai Server is not reachable")	
        #     exit(3)




### fucntion to get the loc in given directory and lang

def getLoc(build_dir,lang):

    lang_extensions = {
        'nodejs':'.js',
        'python':'.py',
        'php':'.php',
        'ruby':'.rb',
        'go':'.go',
        'java':'.java',
        'python-snyk':'.py',
        'node-snyk':'.js',
        'ruby-snyk':'.rb',
        'csharp':'.cs'
    }

    #print(lang_extensions['js'])

    logging.info('Counting the lines of code of the given language. Found: %s',build_dir)
    try:
        return loc.countlines(build_dir,extentsion=lang_extensions[lang])
    except:
        return 0

## this function will mask the middle charecters depending on the lenght of given value and return -- used in trufflehog -- MM
def masker(n):
    var1 = str(n)
    str_length = len(n)

    if str_length > 15:
        total_unmask_char_len = 8
        prefix_char_len = 4
        sufix_char_len = 4
    elif str_length < 10:
        total_unmask_char_len = 4
        prefix_char_len = 2
        sufix_char_len = 2
    elif str_length < 5:
        total_unmask_char_len = 2
        prefix_char_len = 1
        sufix_char_len = 1
    elif str_length < 3:
        masked = '#' * str_length
        return masked

    unmasked_len = str_length - total_unmask_char_len
    masked_value = '#' * unmasked_len

    prefix = var1[:prefix_char_len]

    sufix = var1[-sufix_char_len:]

    masked = prefix+masked_value+sufix
    return masked



def convertXmlToJson(file_name,path,output_file):
    
    # open the input xml file and read
    # data in form of python dictionary
    # using xmltodict module
    target = path+file_name
    output_target = path+output_file

    try:
        with open(target) as xml_file:
            
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            
            # generate the object using json.dumps()
            # corresponding to json data
            
            json_data = json.dumps(data_dict)
            
            # Write the json data to output
            # json file
            with open(output_target, "w") as json_file:
                json_file.write(json_data)
                json_file.close()
            return 1

    except Exception as e:
        return 0




def logError(msg,error):
    f = open("bomancli.errors.log", "a")
    msg = msg+'\n'
    # writing in the file
    now = 'ss'
    f.write('\n===========================================================\n')
    f.write(str(now))
    f.write(str(msg))
    f.write(str(error)) 
     # closing the file
    f.close()



## summary function

def showSummary():
    logging.info('---------------------------------------------------------------------------------------------------------------')
    logging.info('--------------------------  SUMMARY FOR SCAN: %s  -----------------------------------------------',Config.scan_name,)
    logging.info('--------------------------- Scan Token: %s --------------------------------------------------------',Config.scan_token)

    logging.info('-------- SAST STATUS ---------')
    if Config.sast_present == True:
        logging.info('SCAN STATUS: %s',Config.sast_scan_status)
        logging.info('UPLOAD STATUS: %s',Config.sast_upload_status)
        logging.info('SCAN MESSAGE : %s', Config.sast_message)

        logging.info('ERRORS: %s',Config.sast_errors)
    else:
        logging.info('SCAN MESSAGE : %s', Config.sast_message)   
    logging.info('----------------------------------------')

    logging.info('-------- DAST STATUS ---------')
    if Config.dast_present == True:
        logging.info('SCAN STATUS: %s',Config.dast_scan_status)
        logging.info('UPLOAD STATUS: %s',Config.dast_upload_status)
        logging.info('SCAN MESSAGE : %s', Config.dast_message)

        logging.info('ERRORS: %s',Config.dast_errors)
    else:
        logging.info('SCAN MESSAGE : %s', Config.dast_message)    
    logging.info('--------------------------------------')


    
    logging.info('-------- SCA STATUS ---------')
    if Config.sca_present == True:
        logging.info('SCAN STATUS: %s',Config.sca_scan_status)
        logging.info('UPLOAD STATUS: %s',Config.sca_upload_status)
        logging.info('SCAN MESSAGE : %s', Config.sca_message)
        
        logging.info('ERRORS: %s',Config.sca_errors)
    else:
        logging.info('SCAN MESSAGE : %s', Config.sca_message)     
    logging.info('--------------------------------------')



    logging.info('-------- SECRET SCAN STATUS --------- ')
    if Config.secret_scan_present:
        logging.info('SCAN STATUS: %s',Config.secret_scan_status)
        logging.info('UPLOAD STATUS: %s',Config.secret_scan_upload_status)
        logging.info('SCAN MESSAGE : %s', Config.secret_scan_message)
        
        logging.info('ERRORS: %s',Config.secret_scan_errors)
    else:
        logging.info('SCAN MESSAGE : %s', Config.secret_scan_message)   
    logging.info('-------------------------------------')




    # logging.info(Config.sast_message)
    # logging.info(Config.dast_message)
    # logging.info(Config.sca_message)
    # logging.info(Config.secret_scan_message)



def uploadLogs():
    logging.info('Uploading logs for the scan token %s',str(Config.scan_token))
    return 1