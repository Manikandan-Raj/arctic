import os
import json
import requests


class Sumo:
    def __init__(self, logger):
        self.logger = logger
        self.load_env_variables()

    def load_env_variables(self):
        self.sumo_http_collector_url = str(os.environ["SUMO_HTTP_COLLECTOR_URL"])
        
    def send_http_collector(self, searchstring, value):
        try:
            self.logger.info("Hitting sumo url for collector ..")
            payload = json.dumps(value)
            headers = {
                'Accept': 'application/json',
                'Content-type': 'application/json'
            }

            response = requests.request("POST", self.sumo_http_collector_url, headers=headers, data=payload)
            if response.status_code == 200:
                self.logger.info("Search string used in misp for attribute " + searchstring)
                self.logger.info("Response from Misp " + payload)
                self.logger.info("Successfully uploaded the HTTP collector")
        except Exception as e:
            self.logger.info("Exception while hitting http collector " + str(e))