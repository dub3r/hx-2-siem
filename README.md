```
██╗  ██╗██╗  ██╗     ██████╗       ███████╗██╗███████╗███╗   ███╗
██║  ██║╚██╗██╔╝     ╚════██╗      ██╔════╝██║██╔════╝████╗ ████║
███████║ ╚███╔╝█████╗ █████╔╝█████╗███████╗██║█████╗  ██╔████╔██║
██╔══██║ ██╔██╗╚════╝██╔═══╝ ╚════╝╚════██║██║██╔══╝  ██║╚██╔╝██║
██║  ██║██╔╝ ██╗     ███████╗      ███████║██║███████╗██║ ╚═╝ ██║
╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝      ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝
a.k.a. FireEye HX Agent Health 2 SIEM Ingestion Script


Version: 0.0.2
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
```
