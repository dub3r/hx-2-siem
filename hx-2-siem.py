'''
██╗  ██╗██╗  ██╗     ██████╗       ███████╗██╗███████╗███╗   ███╗
██║  ██║╚██╗██╔╝     ╚════██╗      ██╔════╝██║██╔════╝████╗ ████║
███████║ ╚███╔╝█████╗ █████╔╝█████╗███████╗██║█████╗  ██╔████╔██║
██╔══██║ ██╔██╗╚════╝██╔═══╝ ╚════╝╚════██║██║██╔══╝  ██║╚██╔╝██║
██║  ██║██╔╝ ██╗     ███████╗      ███████║██║███████╗██║ ╚═╝ ██║
╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝      ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝

a.k.a. FireEye HX Agent Health 2 SIEM Ingestion Script

Version: 0.0.1
Author: Dan Uber
Twitter: @danub3r


Purpose: I wrote this to ingest HX endpoint data into Splunk, or any other SIEM that can scoop JSON.
         The script is pretty simple, we query the hx/api/v3/hosts API while passing it a customizable
         filter (in this case we're just looking for Online agents). This request returns a huge JSON
         one-liner that contains a list of every online agent in the environment.
         We deserialize that blob from JSON into a Python Object, then iterate through that object 
         to pull out each AgentID. For each AgentID, we then send a query off to the
         hx/api/plugins/host-management/v1/data/ API to pull agent health information. This information
         gets returned to us as another JSON one-liner, which we need to slice to get what we need. 
         We deserialize the agent health information JSON into a Python Object, then we slice out only
         what we need, then we serialize it back into JSON and write it to a file. This allows us to
         `cleanly` ingest the data into a third-party SIEM like Splunk, Security Onion, etc.


Steps: 1. Ensure you have Python3 installed.
       2. Import the modules from the <Modules> section below using `pip3 install <module>`.
       3. On your HX appliance, create an API user, preferably with the "API_Analyst" role.
       4. Throw your API credentials into the <API Credentials> section below.
       5. Place this script in it's own folder. Alternatively, you could run it from location 1 and change the cleanup/output scripts to target location 2.
       6. Leverage Cron or whatever else to handle running the script on an interval.
       7. Configure your SIEM to ingest files it sees created in the targeted output directory.
       8. ...
       9. Profit
'''
###############################################
#                  <Modules>                  #
###############################################
# This is where we define the modules which   #
# we wish to import and leverage within this  #
# script.                                     #
# OS allows us to manipulate the file system. #
# JSON is absolutely necessary, as it's the   #
# format that FireEye spits back at us in the #
# HTTP Response.                              #
# Requests is what we're using to do the HTTP #
# request, including the basic auth string.   #
# URLLib helps us
###############################################
import os, json, requests, urllib
from os import listdir
###############################################
#                 </Modules>                  #
###############################################

###############################################
#               <Filter List>                 #
###############################################
# These filters get URL Encoded and stored in #
# variables, which we then pass into the HTTP #
# Request Address. I've included extras for   #
# conducting additional testing if you wish.  #
###############################################
'''
malwareGuard_Uninstalled = urllib.parse.quote('[{"field":"malwareGuard","arg":["uninstalled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
malwareGuard_Disabled = urllib.parse.quote('[{"field":"malwareGuard","arg":["disabled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
realTimeStatus_Uninstalled = urllib.parse.quote('[{"field":"realTimeStatus","arg":["uninstalled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
realTimeStatus_Disabled = urllib.parse.quote('[{"field":"realTimeStatus","arg":["disabled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
malwareAVstatus_Uninstalled = urllib.parse.quote('[{"field":"malwareAVstatus","arg":["uninstalled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
malwareAVstatus_Disabled = urllib.parse.quote('[{"field":"malwareAVstatus","arg":["disabled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
ExdPluginStatus_Uninstalled  = urllib.parse.quote('[{"field":"ExdPluginStatus","arg":["uninstalled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
ExdPluginStatus_Disabled  = urllib.parse.quote('[{"field":"ExdPluginStatus","arg":["disabled"],"operator":"equals"},{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
'''
encodedFilters = urllib.parse.quote('[{"field":"online","arg":["online"],"operator":"equals"},{"field":"productName","arg":["win"],"operator":"contains"}]', safe='')
###############################################
#              </Filter List>                 #
###############################################


###############################################
#              <API Credentials>              #
###############################################
# This is where we insert our API credentials.#
# These creds get passed with the Web Request #
# below.                                      #
###############################################
hxAPIUser = 'API_Analyst_Username_Goes_Here'
hxAPIPass = 'API_Analyst_Password_Goes_Here'
###############################################
#            </API Credentials>               #
###############################################


###############################################
#                <Web Request>                #
###############################################
# This is the web request that reaches out to #
# our FireEye HX Appliance's RESTful API and  #
# retrieves a JSON formatted list of our      #
# endpoints. The REST API request only has a  #
# single important variable in it, "?limit=", #
# which we can use to limit the output if we  #
# wanted. The web request is done using Basic #
# Auth. The account which we leverage here    #
# must have the "api_analyst" role assigned   #
# to it within our HX Appliance.              #
# responseLimit allows you to limit the       #
# number of agents the API returns per query. #
###############################################
responseLimit = "5"
applianceURL = 'https://EXAMPLE-hx-webui-1.hex01.helix.apps.fireeye.com'
emit = requests.get(applianceURL + '/hx/api/v3/hosts?limit=' + responseLimit + '&filter=' + encodedFilters, auth=(hxAPIUser, hxAPIPass))
###############################################
#               </Web Request>                #
###############################################




# This deserializes the JSON into a Python 
# Dictionary Object, stored in the "data" variable.
hostsData = json.loads(emit.text)

# File Manipulation Section - Keep in mind that you might need an extra backslash to prevent the trailing ' from being escaped.
workingPath = '\Example\Path'
for file in listdir(workingPath):
    if file.endswith('.json'):
        os.remove(workingPath + file)


# Main Section
# If we have results from the first request, do stuff.
# Notice that we're only taking an inner slice of the python dictionary object. 
# This is what allows Splunk to read it in a legible format.
# Otherwise
if hostsData['data']['total'] > 0:
    # Set iterator to 0
    entry = 0
    # This should step through each object in the JSON object we got earlier.
    while entry < (hostsData['data']['total']):
        # sub-query to pull host-management data from HX
        r2 = requests.get(applianceURL + '/hx/api/plugins/host-management/v1/data/' + hostsData['data']['entries'][entry]['_id'], auth=(hxAPIUser, hxAPIPass))
        # deserialize the retrieved host-management api json blob into a python dictionary
        agentData = json.loads(r2.text)

        # Here we're writing the file to disk with a hard-coded filename containing the "hostname" + "agent ID" + ".json" extension.
        # Notice that we need to step into the nested arrays ['data']['data'] to get hostname and id.
        with open(workingPath + agentData['data']['data']['hostname'] + '-' + agentData['data']['data']['id'] + '.json', "w") as out:
            # Notice that we're only taking an inner slice of the python dictionary object. This is what allows Splunk to read it in a legible format.
            json.dump(agentData['data']['data'], out)
        # Here we're just increasing the iterator +1, a looping standard.
        entry += 1
