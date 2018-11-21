import time
import collections
import random
import math
import string
import sys

import requests
import base64
import urllib
import hmac
import hashlib

from schema import Schema, And, Use, SchemaError
from argparse import ArgumentParser


''' Use this function to validate the answers provided to the script by the user '''


def validateAnswers(questions_schema, validate_answers):
    try:
        questions_schema.validate(validate_answers)
        return True
    except SchemaError:
        return False


class Gallery(object):
    def __init__(self, apiLocation, apiKey, apiSecret, apiVerbose):
        self.apiLocation = 'http://' + apiLocation + '/gallery/api/v1'
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        self.apiVerbose = apiVerbose

    def buildOauthParams(self):
        return {'oauth_consumer_key': self.apiKey,
                'oauth_nonce': self.generate_nonce(5),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': str(int(math.floor(time.time()))),
                'oauth_version': '1.0'}

    '''Finds workflows in a subscription'''

    def subscription(self, search=""):
        method = 'GET'
        url = self.apiLocation + '/workflows/subscription/'
        params = self.buildOauthParams()
        if search != "":
            params.update({'search': search})
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Returns the questions for the given Alteryx Analytics App'''

    def questions(self, appId):
        method = 'GET'
        url = self.apiLocation + '/workflows/' + appId + '/questions/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Queue an app execution job. Returns ID of the job'''

    def executeWorkflow(self, appId, **kwargs):
        method = 'POST'
        url = self.apiLocation + '/workflows/' + appId + '/jobs/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        if 'payload' in kwargs:

            if self.apiVerbose:
                print('Payload included: %s' % kwargs['payload'])

            payload_data = kwargs['payload']

            try:
                output = requests.post(url, json=payload_data, headers={'Content-Type': 'application/json'}, params=params)
                output.raise_for_status()
            except requests.exceptions.HTTPError as err:
                print(err)
                sys.exit(err)
            except requests.exceptions.RequestException as err2:
                print(err2)
                sys.exit(err2)

        else:
            if self.apiVerbose:
                print('No Payload included')

            try:
                output = requests.post(url, params=params)
                output.raise_for_status()
            except requests.exceptions.HTTPError as err:
                print(err)
                sys.exit(err)
            except requests.exceptions.RequestException as err2:
                print(err2)
                sys.exit(err2)

        return output, output.json()

    '''Returns the jobs for the given Alteryx Analytics App'''

    def getJobs(self, appId):
        method = 'GET'
        url = self.apiLocation + '/workflows/' + appId + '/jobs/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Retrieves the job and its current state'''

    def getJobStatus(self, jobId):
        method = 'GET'
        url = self.apiLocation + '/jobs/' + jobId + '/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Returns the output for a given job (FileURL)'''

    def getJobOutput(self, jobID, outputID):
        method = 'GET'
        url = '/jobs/' + jobID + '/output/' + outputID + '/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Returns the App that was requested'''

    def getApp(self, appId):
        method = 'GET'
        url = self.apiLocation + '/' + appId + '/package/'
        params = self.buildOauthParams()
        signature = self.generateSignature(method, url, params)
        params.update({'oauth_signature': signature})

        try:
            output = requests.get(url, params=params)
            output.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(err)
        except requests.exceptions.RequestException as err2:
            print(err2)
            sys.exit(err2)

        return output, output.json()

    '''Generate pseudo-random number'''

    def generate_nonce(self, length=5):
        return ''.join([str(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)) for i in
                        range(length)])

    """Returns HMAC-SHA1 signature"""

    def generateSignature(self, httpMethod, url, params):
        # Moved imports to global because every run requires the signature

        q = lambda x: requests.utils.quote(x, safe="~")
        sorted_params = collections.OrderedDict(sorted(params.items()))

        # Python 3 moved urlencode to urllib.parse
        normalized_params = urllib.parse.urlencode(sorted_params)
        base_string = "&".join((httpMethod.upper(), q(url), q(normalized_params)))

        # Python 3 requires string in bytes for hmac.new()
        secret_bytes = bytes("&".join([self.apiSecret, '']), 'ascii')
        base_bytes = bytes(base_string, 'ascii')
        sig = hmac.new(secret_bytes, base_bytes, hashlib.sha1)

        # Python 3 requires use of b64encode method from base64
        return base64.b64encode(sig.digest())


if __name__ == '__main__':

    # This section of code is responsible for handling the inputs passed into this program from the command line
    ap = ArgumentParser(description="Python Command Line Interface for sending requests to the Alteryx Server")

    # Define the required and optional parameters - the Python application will fail if required inputs are not provided
    ap.add_argument("server",
                    type=str,
                    help="gallery server name e.g. l4dwidap7125")
    ap.add_argument("key",
                    type=str,
                    help="gallery subscription key")
    ap.add_argument("secret",
                    type=str,
                    help="gallery subscription secret")

    # Define 2 parameters that are mutually exclusive but one of them is required
    g1 = ap.add_mutually_exclusive_group(required=True)
    g1.add_argument("-s", "--submit",
                    type=str,
                    metavar='S',
                    help="search for an App and submit it")
    g1.add_argument("-t", "--status",
                    type=str,
                    metavar='T',
                    help="get status of running App using a Job Id")

    # Define remaining optional parameters
    ap.add_argument("-a", "--answers",
                    type=str,
                    metavar='A',
                    help="list of answers to app questions, implies -s")
    ap.add_argument("-v", "--verbose",
                    help="log more information to the output, default is false",
                    action="store_true")

    # The final step is to create an object with the args inside it
    args = ap.parse_args()

    # Create the Gallery object connection with the 3 core data elements needed for further processing
    con = Gallery(args.server, args.key, args.secret, args.verbose)

    # To submit an App to run
    if args.submit:

        # Make the call to the Gallery connection to find the app id
        response, data = con.subscription(args.submit)

        # Save this one because we'll need it multiple times
        appId = data[0]['id']

        if args.verbose:
            print("Response Code: ", response.status_code)
            print("Subscription: ", data)
            print("App Id: ", appId)
            print("Package Type: ", data[0]['packageType'])
            print("Name: ", data[0]['metaInfo']['name'])
            print("Is Chained?: ", data[0]['isChained'])
        else:
            print("App Id: ", appId)

        # Package Type is an Analytic App (packageType = 0)
        if data[0]['packageType'] == 0:
            # Make the call to the Gallery connection to get any questions for the App
            response, data = con.questions(appId)

            if args.verbose:
                print("Response Code: ", response.status_code)
                print("Questions: ", data)

            # If there are no questions (empty list)
            if not data:
                # If the user passed answers to questions, let them know that the answers aren't needed
                if args.answers:
                    print("There are no Questions for this Analytic App, so the -A argument is ignored.")

                # Make the call to the Gallery connection to submit the App
                response, data = con.executeWorkflow(appId)

            # If there are questions (non-empty list)
            else:
                # Check to see if the Answers provided are structured correctly
                if args.answers:

                    # Convert Answers string to a dictionary
                    try:
                        answers = eval(args.answers)
                    except Exception as e:
                        print("type error: " + str(e))
                    finally:
                        print("Answers type: {}, Answers: {}".format(type(answers), answers))
                        print(answers['questions'])

                    # Define the valid schema
                    valid_schema = Schema({
                        'questions': [{
                            'name': And(Use(str)),
                            'value': And(Use(str))
                        }]
                    })

                    # Determine what to do
                    if not validateAnswers(valid_schema, answers):
                        print("Question answers provided with the -A argument are not valid!")
                        sys.exit("Question answers provided with the -A argument are not valid!")
                    else:
                        print("Answers are valid.")
                        # Make the call to the Gallery connection to submit the App
                        response, data = con.executeWorkflow(appId, payload=answers)

                else:
                    print("This Analytic App requires answers to questions.")
                    sys.exit("This Analytic App requires answers to questions.")

        # Package Type is a Standard Workflow (packageType = 1)
        elif data[0]['packageType'] == 1:
            # Make the call to the Gallery connection to submit the App (standard workflow)
            response, data = con.executeWorkflow(appId)

        # Some other Package Type (note - we do not want to run in the Gallery
        else:
            print("This workflow type cannot be run from the API.")
            sys.exit("This workflow type cannot be run from the API.")

        # Save this one because we'll need it multiple times
        jobId = data['id']

        if args.verbose:
            print("Response Code: ", response.status_code)
            print("Job Queued?: ", data)
            print("Job Id: ", jobId)
            print("Create Date: ", data['createDate'])
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])
            print("Outputs: ", data['outputs'])
            print("Messages: ", data['messages'])
        else:
            print("Job Id: ", jobId)
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])

        # Make the call to the Gallery connection to check the Job status before exiting the application
        response, data = con.getJobStatus(jobId)

        if args.verbose:
            print("Response Code: ", response.status_code)
            print("Job Status: ", data)
            print("Job Id: ", data['id'])
            print("Create Date: ", data['createDate'])
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])
            print("Outputs: ", data['outputs'])
            print("Messages: ", data['messages'])
        else:
            print("Job Id: ", data['id'])
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])

    # To get status for a running Job
    elif args.status:

        response, data = con.getJobStatus(args.status)

        if args.verbose:
            print("Response Code: ", response.status_code)
            print("Job Status: ", data)
            print("Job Id: ", data['id'])
            print("Create Date: ", data['createDate'])
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])
            print("Outputs: ", data['outputs'])
            print("Messages: ", data['messages'])
        else:
            print("Job Id: ", data['id'])
            print("Status: ", data['status'])
            print("Disposition: ", data['disposition'])

    else:
        print("Must provide either submit or status information.")
        sys.exit("Must provide either submit or status information.")
