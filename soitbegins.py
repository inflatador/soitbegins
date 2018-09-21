#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# soitbegins, a script that imports an image and sets necessary image metadata properties
# version: 0.0.1a
# Copyright 2018 Brian King
# License: Apache

import argparse
import datetime
from getpass import getpass
import json
import keyring
import os
import plac

import re
import requests
import sys
import time
from time import time

def find_endpoints(auth_token, region, desired_service="cloudImages"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    headers = {'content-type': 'application/json', 'Accept': 'application/json',
               'X-Auth-Token': auth_token}
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]
    for service in range(len(endpoints)):
        if desired_service == endpoints[service]["name"] and region == endpoints[service]["region"]:
            desired_endpoint = endpoints[service]["publicURL"]
    return desired_endpoint, headers

def getset_keyring_credentials(username=None, password=None):
    """Method to retrieve credentials from keyring."""
    username = keyring.get_password("raxcloud", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
        elif creds == "username":
            username = input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("raxcloud", "password")
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("raxcloud", 'password' , password)
        print ("API key value saved in keychain as raxcloud password.")
    return username, password

def wipe_keyring_credentials(username, password):
    """Wipe credentials from keyring."""
    try:
        keyring.delete_password('raxcloud', 'username')
        keyring.delete_password('raxcloud', 'password')
    except:
        pass

    return True

# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]
    return auth_token

def check_for_cf_object(files_endpoint, headers, cf_container, cf_object, region):
    object_url = ("%s/%s/%s" % (files_endpoint, cf_container, cf_object))
    object_check = requests.head(url=object_url, headers=headers)

    if object_check.status_code == 404:
        print ("Error! Couldn't find object %s in container %s in region %s." % (cf_object, cf_container, region))

    return object_url

def import_image(images_endpoint, headers, cf_container, cf_object):
    image_name = cf_object.split('.')[0]
    image_url = ("%s/tasks" % (images_endpoint))
    import_string = ("%s/%s" % (cf_container, cf_object))
    image_data = {'type': 'import',
                  'input': {
                      'image_properties': {
                          'name': image_name
                      },
                      'import_from': import_string
                  }}
    raw_import_task = requests.post(url=image_url, headers=headers, json=image_data)
    raw_import_task.raise_for_status()
    import_task = raw_import_task.json()
    import_task_id = import_task["id"]
    return import_task_id

def check_import_status(images_endpoint, headers, import_task_id):
    import_task_url = ("%s/tasks/%s" % (images_endpoint, import_task_id))
    print (import_task_url)

#begin main function
@plac.annotations(
    region = plac.Annotation("Rackspace Cloud Servers region"),
    cf_container = plac.Annotation("Cloud Files container that has the VHD file"),
    cf_object = plac.Annotation("Filename of the VHD file (aka Cloud Files object)")
                )
def main(region, cf_container, cf_object):
    username,password = getset_keyring_credentials()

    auth_token = get_auth_token(username, password)

    images_endpoint, headers = find_endpoints(auth_token, region, desired_service="cloudImages")

    files_endpoint, headers  = find_endpoints(auth_token, region, desired_service="cloudFiles")

    object_url = check_for_cf_object(files_endpoint, headers, cf_container, cf_object, region)

    import_task_id = import_image(images_endpoint, headers, cf_container, cf_object)

    check_import_status(images_endpoint, headers, import_task_id)

    #this might violate DRY, I will fix later.



if __name__ == '__main__':
    import plac
    plac.call(main)
