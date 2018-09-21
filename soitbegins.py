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
# from time import time

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
        print ("Error! I checked region %s, but couldn't find object %s in container %s." % (region, cf_object, cf_container))
    else:
        print ("I found object %s in container %s in the %s region." % (cf_object, cf_container, region))

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
    print ("Spawned import task for image %s . Import task ID is %s" % (cf_object, import_task_id))
    return import_task_id

def check_import_status(images_endpoint, headers, import_task_id):
    import_task_url = ("%s/tasks/%s" % (images_endpoint, import_task_id))
    import_status = ""
    while import_status != "success":
        try:
            import_status_check = requests.get(url=import_task_url, headers=headers)
        except requests.ConnectionError as e:
            print("Can't connect to API, trying again...")
        if import_status_check.status_code == 200:
            import_status = import_status_check.json()["status"]
            import_message = import_status_check.json()["message"]
        if import_status == "failed":
            print ('''
            Error! Image import failed with message %s.
            See https://developer.rackspace.com/docs/cloud-images/v2/api-reference/image-task-operations/
            for error codes." % (import_message)
            ''')
        import_status_output = "Image import is in '%s' status..." % (import_status)
        sys.stdout.write(import_status_output)
        sys.stdout.flush()

        if import_status == "processing":
            import_status_postpend = "checking again in 30 seconds..."
            sys.stdout.write(import_status_postpend)
            sys.stdout.flush()
            time.sleep(30)
    #After the task succeeds, we can get the image ID
    image_id_check = requests.get(url=import_task_url, headers=headers)
    image_id = image_id_check.json()["result"]["image_id"]
    print ("New image imported successfully! Image ID is %s" % (image_id))
    return image_id

def set_image_metadata(cs_endpoint, headers, image_id):
    # check to see if the image is there.
    image_url = ("%s/images/%s" % (cs_endpoint, image_id))
    # image_url = "https://iad.servers.api.rackspacecloud.com/v2/766030/images/8c157ae6-5b56-4739-8cba-f3831f3dbe2e"
    # print (image_url)
    image_exists_check = requests.get(url=image_url, headers=headers)
    image_exists_check.raise_for_status()
    metadata_url = ("%s/images/%s/metadata" % (cs_endpoint, image_id))
    # The following image metadata key/value pairs are needed for
    # maximum importability into Rackspace Public Cloud
    needed_metadata = {
        "metadata": {
            "vm_mode": "hvm",
            "xenapi_use_agent": "False",
            "img_config_drive": "mandatory",
            "com.rackspace__1__resize_disk": False,
            "ssh_user": "admin"
                    }
                        }
    metadata_addition = requests.post(url=metadata_url, headers=headers, json=needed_metadata)
    metadata_addition.raise_for_status()
    print ("Success! I set the values %s on newly-imported image %s." % (needed_metadata, image_id))




#begin main function
@plac.annotations(
    region = plac.Annotation("Rackspace Cloud Servers region"),
    cf_container = plac.Annotation("Cloud Files container that has the VHD file"),
    cf_object = plac.Annotation("Filename of the VHD file (aka Cloud Files object)")
                )
def main(region, cf_container, cf_object):
    username,password = getset_keyring_credentials()

    auth_token = get_auth_token(username, password)

    #FIXME: This violates DRY

    images_endpoint, headers = find_endpoints(auth_token, region, desired_service="cloudImages")

    files_endpoint, headers = find_endpoints(auth_token, region, desired_service="cloudFiles")

    cs_endpoint, headers = find_endpoints(auth_token, region, desired_service="cloudServersOpenStack")

    #Not using the object URL at the moment, but could use this to delete the object after import.
    object_url = check_for_cf_object(files_endpoint, headers, cf_container, cf_object, region)

    import_task_id = import_image(images_endpoint, headers, cf_container, cf_object)

    image_id = check_import_status(images_endpoint, headers, import_task_id)

    set_image_metadata(cs_endpoint, headers, image_id)



if __name__ == '__main__':
    import plac
    plac.call(main)
