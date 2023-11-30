# Tests OpenEMR API Endpoints

## imports
import argparse
import json
import requests
import base64
import uuid
import urllib.parse
import tkinter as tk

## parse out user input for ALB URL
parser = argparse.ArgumentParser(description="OpenEMR API Endpoint Testing Script",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("LoadBalancerURL", help="Load balancer URL to use for testing.")
args = parser.parse_args()
config = vars(args)
alb_url = config['LoadBalancerURL']

## Use the OpenEMR API to register a new client application
reqUrl = "https://"+alb_url+"/oauth2/default/registration"
headersList = {"Content-Type": "application/json"}

## The values below can be altered as one would wish
payload = json.dumps(
  {
    "application_type": "private",
    "redirect_uris": ["https://"+alb_url+"/swagger/oauth2-redirect.html"],
    "initiate_login_uri": "https://"+alb_url+"/swagger/index.html",
    "post_logout_redirect_uris": [""],
    "client_name": "TestApp",
    "token_endpoint_auth_method": "client_secret_post",
    "contacts": ["user@example.com"],
    "scope": 'openid offline_access launch/patient api:fhir ' +
      'patient/AllergyIntolerance.read patient/Appointment.read ' +
      'patient/Binary.read patient/CarePlan.read patient/CareTeam.read ' +
      'patient/Condition.read patient/Coverage.read patient/Device.read ' +
      'patient/DiagnosticReport.read patient/DocumentReference.read ' +
      'patient/DocumentReference.$docref patient/Encounter.read ' +
      'patient/Goal.read patient/Immunization.read patient/Location.read ' +
      'patient/Medication.read patient/MedicationRequest.read ' +
      'patient/Observation.read patient/Organization.read ' +
      'patient/Patient.read patient/Person.read patient/Practitioner.read ' +
      'patient/Procedure.read patient/Provenance.read ' +
      'user/Binary.read user/CarePlan.read user/CareTeam.read user/Condition.read ' +
      'user/Coverage.read user/Device.read user/DiagnosticReport.read ' +
      'user/DocumentReference.read user/DocumentReference.$docref ' +
      'user/Encounter.read user/Goal.read user/Immunization.read ' +
      'user/Location.read user/Medication.read user/MedicationRequest.read ' +
      'user/Observation.read user/Organization.read user/Organization.write ' +
      'user/Patient.read user/Patient.write user/Person.read ' +
      'user/Practitioner.read user/Practitioner.write user/PractitionerRole.read ' +
      'user/Procedure.read user/Provenance.read'
  }
)

## Send our payload to the server and get our response.
response = requests.request("POST", reqUrl, data=payload,  headers=headersList, verify=False)

## Get the JSON of the response
client_app = response.json()

## Print client app details
print(client_app)

## Prompt user to enable client with ID above before pressing enter to continue.
input('Enable the client with the ID above. Push enter to continue.')

## Get the code we can use to create a token
reqUrl = "https://"+alb_url+"/oauth2/default/authorize"
headersList = {"Content-Type": "application/json"}
uuid = str(uuid.uuid4())

## Notice the state, redirect_uri, and scope must match pervious values
payload = {
    "client_id": client_app['client_id'],
    "access_code": client_app['registration_access_token'],
    "response_type": "code",
    "state": uuid,
    "redirect_uri": "https://"+alb_url+"/swagger/oauth2-redirect.html",
    "scope": 'openid offline_access launch/patient api:fhir ' +
      'patient/AllergyIntolerance.read patient/Appointment.read ' +
      'patient/Binary.read patient/CarePlan.read patient/CareTeam.read ' +
      'patient/Condition.read patient/Coverage.read patient/Device.read ' +
      'patient/DiagnosticReport.read patient/DocumentReference.read ' +
      'patient/DocumentReference.$docref patient/Encounter.read ' +
      'patient/Goal.read patient/Immunization.read patient/Location.read ' +
      'patient/Medication.read patient/MedicationRequest.read ' +
      'patient/Observation.read patient/Organization.read ' +
      'patient/Patient.read patient/Person.read patient/Practitioner.read ' +
      'patient/Procedure.read patient/Provenance.read ' +
      'user/Binary.read user/CarePlan.read user/CareTeam.read user/Condition.read ' +
      'user/Coverage.read user/Device.read user/DiagnosticReport.read ' +
      'user/DocumentReference.read user/DocumentReference.$docref ' +
      'user/Encounter.read user/Goal.read user/Immunization.read ' +
      'user/Location.read user/Medication.read user/MedicationRequest.read ' +
      'user/Observation.read user/Organization.read user/Organization.write ' +
      'user/Patient.read user/Patient.write user/Person.read ' +
      'user/Practitioner.read user/Practitioner.write user/PractitionerRole.read ' +
      'user/Procedure.read user/Provenance.read'
}

## Create a URL for the user to visit to authorize the application. You should log in with the admin user and password at the below URL.
url_to_visit_for_authorization = "https://"+alb_url+"/oauth2/default/authorize?" + urllib.parse.urlencode(payload)
input("Please authorize at the following URL ..." + url_to_visit_for_authorization +  "... and then press enter to continue. ")
input('Copy the code in the redirect link and then press enter.')

## Get code from clipboard with Tkinter
root = tk.Tk()
root.withdraw()
code = str(root.clipboard_get())
print("code is " + code)

## Get token using the code we got from the redirect URL.
session = requests.Session()
session.verify = False

string_to_convert_to_base64 = client_app['client_id']+':'+client_app['client_secret']
base64_bytes = base64.b64encode(string_to_convert_to_base64.encode("ascii"))
base64_string = base64_bytes.decode("ascii")

## The "Authorization" header here is very important in this call.
session.headers.update({
    'Accept': 'application/json',
    'Authorization': f"Basic {base64_string}",
    "Content-Type": "application/x-www-form-urlencoded"
})

## Payload must use the code obtained above and having matching values for previous calls for client_id, grant_type, and redirect_uri.
payload = {
    "client_id": client_app['client_id'],
    "grant_type": "authorization_code",
    "redirect_uri": "https://"+alb_url+"/swagger/oauth2-redirect.html",
    "code": code
}

## Retrieve our token from the server
token = session.post(
    url = str('https://'+alb_url+'/oauth2/default/token'),
    data = payload
).json()

## Print token and the rest of the response out.
print(token)