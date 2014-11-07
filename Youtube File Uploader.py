import httplib
import httplib2
import os
import random
import sys
import time
import argparse
import datetime

from apiclient.discovery import build
from apiclient.errors import HttpError
from apiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow


# Explicitly tell the underlying HTTP transport library not to retry, since
# we are handling retry logic ourselves.
httplib2.RETRIES = 1

# Maximum number of times to retry before giving up.
MAX_RETRIES = 10

# Always retry when these exceptions are raised.
RETRIABLE_EXCEPTIONS = (httplib2.HttpLib2Error, IOError, httplib.NotConnected,
  httplib.IncompleteRead, httplib.ImproperConnectionState,
  httplib.CannotSendRequest, httplib.CannotSendHeader,
  httplib.ResponseNotReady, httplib.BadStatusLine)

# Always retry when an apiclient.errors.HttpError with one of these status
# codes is raised.
RETRIABLE_STATUS_CODES = [500, 502, 503, 504]

# The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
# the OAuth 2.0 information for this application, including its client_id and
# client_secret. You can acquire an OAuth 2.0 client ID and client secret from
# the Google Developers Console at
# https://console.developers.google.com/.
# Please ensure that you have enabled the YouTube Data API for your project.
# For more information about using OAuth2 to access the YouTube Data API, see:
#   https://developers.google.com/youtube/v3/guides/authentication
# For more information about the client_secrets.json file format, see:
#   https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows an application to upload files to the
# authenticated user's YouTube channel, but doesn't allow other types of access.
YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"

# This variable defines a message to display if the CLIENT_SECRETS_FILE is
# missing.
MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make this sample run you will need to populate the client_secrets.json file
found at:

   %s

with information from the Developers Console
https://console.developers.google.com/

For more information about the client_secrets.json file format, please visit:
https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
""" % os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   CLIENT_SECRETS_FILE))

VALID_PRIVACY_STATUSES = ("public", "private", "unlisted")


def get_authenticated_service(args):
  flow = flow_from_clientsecrets(CLIENT_SECRETS_FILE,
    scope=YOUTUBE_UPLOAD_SCOPE,
    message=MISSING_CLIENT_SECRETS_MESSAGE)

  storage = Storage("%s-oauth2.json" % sys.argv[0])
  credentials = storage.get()

  if credentials is None or credentials.invalid:
    credentials = run_flow(flow, storage, args)

  return build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION,
    http=credentials.authorize(httplib2.Http()))

def initialize_upload(youtube, options):
  tags = None
  if options.keywords:
    tags = options.keywords.split(",")

  body=dict(
    snippet=dict(
      title=options.title,
      description=options.description,
      tags=tags,
      categoryId=options.category
    ),
    status=dict(
      privacyStatus=options.privacyStatus
    )
  )

  # Call the API's videos.insert method to create and upload the video.
  insert_request = youtube.videos().insert(
    part=",".join(body.keys()),
    body=body,
    # The chunksize parameter specifies the size of each chunk of data, in
    # bytes, that will be uploaded at a time. Set a higher value for
    # reliable connections as fewer chunks lead to faster uploads. Set a lower
    # value for better recovery on less reliable connections.
    #
    # Setting "chunksize" equal to -1 in the code below means that the entire
    # file will be uploaded in a single HTTP request. (If the upload fails,
    # it will still be retried where it left off.) This is usually a best
    # practice, but if you're using Python older than 2.6 or if you're
    # running on App Engine, you should set the chunksize to something like
    # 1024 * 1024 (1 megabyte).
    media_body=MediaFileUpload(options.file, chunksize=-1, resumable=True)
  )

  resumable_upload(insert_request)

# This method implements an exponential backoff strategy to resume a
# failed upload.
def resumable_upload(insert_request):
  response = None
  error = None
  retry = 0
  while response is None:
    try:
      print "Uploading file..."
      status, response = insert_request.next_chunk()
      if 'id' in response:
        print "Video id '%s' was successfully uploaded." % response['id']
      else:
        exit("The upload failed with an unexpected response: %s" % response)
    except HttpError, e:
      if e.resp.status in RETRIABLE_STATUS_CODES:
        error = "A retriable HTTP error %d occurred:\n%s" % (e.resp.status,
                                                             e.content)
      else:
        raise
    except RETRIABLE_EXCEPTIONS, e:
      error = "A retriable error occurred: %s" % e

    if error is not None:
      print error
      retry += 1
      if retry > MAX_RETRIES:
        exit("No longer attempting to retry.")

      max_sleep = 2 ** retry
      sleep_seconds = random.random() * max_sleep
      print "Sleeping %f seconds and then retrying..." % sleep_seconds
      time.sleep(sleep_seconds)

#This segment was adapted from the youtube API sample. It has been modified so that it contains all the
#arguements needed to pass the file into the API. The variables are the only items that most people should change.
#the authentication is nessicary to make sure you are logging into a valid youtube account and it runs before every
#video is uploaded. Because of this modification the application cannot be run with arguements from the console.
def video_upload(fileName, fileTitle, fileDesc, fileCat, fileKey, filePriv):
  parser = argparse.ArgumentParser(prog='PROG')
  parser.add_argument("--auth_host_name", help="Authentication host name", default="localhost")
  parser.add_argument("--auth_host_port", help="Authentication host port", default=["8080", "8090"])
  parser.add_argument("--category", default="22",
    help="Numeric video category. " +
      "See https://developers.google.com/youtube/v3/docs/videoCategories/list")
  parser.add_argument("--description", help="Video description",
    default="Test Description")
  parser.add_argument("--file", required=True, help="Video file to upload")
  parser.add_argument("--keywords", help="Video keywords, comma separated",
    default="")
  parser.add_argument("--logging_level", help="NA", default="ERROR")
  parser.add_argument("--noauth_local_webserver", help="NA", default="False")
  parser.add_argument("--privacyStatus", choices=VALID_PRIVACY_STATUSES,
    default=VALID_PRIVACY_STATUSES[0], help="Video privacy status.")
  parser.add_argument("--title", help="Video title", default="Test Title")
  
  

  args = parser.parse_args(["--logging_level", "ERROR", "--noauth_local_webserver", "True", "--auth_host_name", "localhost", "--auth_host_port", ["8080", "8090"], "--file", fileName, "--title", fileTitle, "--description", fileDesc, "--category", "22", "--keywords", fileKey, "--privacyStatus", filePriv])


  if not os.path.exists(args.file):
    exit("Please specify a valid file using the --file= parameter.")

  youtube = get_authenticated_service(args)
  try:
    initialize_upload(youtube, args)
  except HttpError, e:
    print "An HTTP error %d occurred:\n%s" % (e.resp.status, e.content)


  try:
    initialize_upload(youtube, args)
  except HttpError, e:
    print "An HTTP error %d occurred:\n%s" % (e.resp.status, e.content)

#This is the path where the videos will be saved. I reccomend saving all the files to the same folder, without creating new folders for each day.
ytPath = "C:/video"


hRunning = True

#There is no built in termination for this application. The file will continue running until it is stopped
while hRunning == True:
    #This makes a list of all files in the folder. This is needed to make sure that all video files are located. 
    #This has to be updated every time the system runs through otherwise it will not detect any new files.
    listing = os.listdir(ytPath)
    for yFile in listing:
        #The files used for testing were mp4. This segment checks the file type and if it finds mp4 it will continue
        #processing the file. This prevents a lockup that will cause the system to keep trying to upload an invalid
        #file type.
        yfLen = len(yFile) - 3
        if yFile [yfLen:] == "mp4":
            #This section is parsing out the file name so it can be made readable for a youtube video. The files
            #used for testing had 25 character filenames with date and time included. This will need to be adjusted
            #to fit the file name. Each file uploaded should have a different name and attaching the date and time
            #will make it easier to find the timeframe of the video you are looking for.
            desc1 = yFile [13:21]
            desc1 = desc1.replace("-",":")
            desc2 = yFile [2:12]
            desc2 = desc2.replace("-","/")
            desc = desc2 + " " + desc1
            #This prints out the description of the file to the console. In this case it is the date and time of 
            #the video.
            print desc
            ytFile = ytPath + yFile
            #video_upload("Filename and path", "Video Title", "Video Description", "Category", "Keywords(comma seperated)", 
            #"Privacy settings(public, unlisted, or private)")
            video_upload(ytFile, desc, desc, "22", "","private")
            #This deletes the file from local storage. It is a self cleaning protocol and makes sure you dont upload
            #duplicates. This can be changed to move the file instead, but the file needs to be out of the file path
            #before the system runs again.
            os.remove(ytFile)
    #Once all the files in the folder have been processed the application will print the date and time of completion.
    #The application then sleeps for 10 minutes before checking the folder and uploading new videos. This can be
    #modified without any issues.
    print datetime.datetime.now()
    time.sleep(600)        
