import requests
import json
import os
import sumo
import time
class MISP:
    def __init__(self, logger):
        self.logger = logger
        self.load_env_variables()
        self.retry_count = 1
        self.sumo = sumo.Sumo(self.logger)

    def load_env_variables(self):
        self.misp_url = str(os.environ["MISP_SEARCH_URL"])
        self.authorization = str(os.environ["MISP_AUTHORIZATION"])

    def search_attribute(self, name, value):
        try:
            payload = json.dumps({
                "value": value
            })
            headers = {
                'Authorization': self.authorization,
                'Accept': 'application/json',
                'Content-type': 'application/json'
            }

            response = requests.request("POST", self.misp_url, headers=headers, data=payload)
            if response.status_code == 200:
                data = response.json()
                attribute = data["response"]["Attribute"]
                if len(attribute) > 0:
                    if name == "CS_ALL_HIGH":
                        result = self.remove_data_from_existing(attribute)
                        if len(result) > 0:
                            data = {"response" : { "Attribute" : result }}
                            data_to_sumo = {name: data}
                            self.logger.info("Hit MISP : " + str(name))
                            self.sumo.send_http_collector(payload, data_to_sumo)
                    else:
                        data_to_sumo = {name: data}
                        self.logger.info("Hit MISP : " + str(name))
                        self.sumo.send_http_collector(payload, data_to_sumo)

        except Exception as e:
            self.logger.info("Exception while searching misp attribute" + str(e))
            
            while self.retry_count <= 5:
                self.retry_count += 1
                time.sleep(self.retry_count * 60)
                self.search_attribute(value)
        finally:
            self.retry_count = 1
    
    def remove_data_from_existing(self, attribute):
        processed_attributes = []
        for attrib in attribute:
            if attrib["event_id"] != "1512": # Specific to company, change this on need
                processed_attributes.append(attrib)
        return processed_attributes