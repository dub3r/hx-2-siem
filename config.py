

###############################################
#               <Configuration>               #
###############################################
# hxAPIUser:     Insert your username which   #
#              you configured in your HX      # 
#              Console with the API_Analyst   #
#              Role.                          #
#                                             # 
# hxAPIPass:     Insert above user's          #
#              password, as configured in the #
#              HX Console.                    #
#                                             # 
# workingPath:   The directory where all of the #
#              .json output files will go.    # 
#              ***IMPORTANT*** Make sure you #
#              include a trailing slash!!!    #
#              This is where we tell our SIEM #
#              to watch and ingest any files  #
#              that it sees. Remember that if #
#              you're doing a Windows path,   #
#              you need a double backslash at #
#              the end, because backslashes   #
#              are escape characters in       #
#              Python3.                       #
#                                             # 
# limit:         This will limit the JSON     #
#              response to only return a      #
#              limited number of endpoints.   #
#              If you limit the output,       # 
#              it is normal to get an error:  #
#              "list index out of range"      #
#              because our while loop's       # 
#              condition iterates through     # 
#              ['data']['total'], which does  # 
#              not reflect the limit, rather  # 
#              the environment's total number # 
#              of agents.                     #
#                                             # 
# applianceURL:  This is your HX WebUI URL.   #
#              The example I've included      #
#              below should be similar to     # 
#              what your environment has.     #
#              Please go from https:// to the #
#              .com. Don't include a trailing #
#              slash after the .com or any    #
#              other path after .com, as that #
#              information gets built into    #
#              the requests below.            #
#                                             #
# logFile:       Define an output file name   #
#              for this script's internal log #
#              output.                        # 
#                                             #
# logging:       This value toggles logging.  # 
#              1 = Logging Enabled            #
#              0 = Logging Disabled           #
#                                             #
###############################################
hxAPIUser = 'EXAMPLE_USER'
hxAPIPass = 'EXAMPLE_PASS'
workingPath = 'EXAMPLE\WORKING\PATH'
limit = "50000"
applianceURL = 'https://EXAMPLE-hx-webui-1.hex01.helix.apps.fireeye.com'
logFileName = 'hx2siem.log'
logging = 0
###############################################
#             </Configuration>                #
###############################################