import os
import requests
import json
import time

class AddAttribute:
    def __init__(self, logger):
        self.logger = logger
        self.load_env_variables()
        self.attribute_events_values = []
        
    def load_env_variables(self):
        self.event_attribute_list_url = str(os.environ["EVENT_ATTRIBUTE_LIST_URL"])
        self.add_attribute_url = str(os.environ["ADD_ATTRIBUTE_URL"])
        self.authorization = str(os.environ["MISP_AUTHORIZATION"])
        
        if self.event_attribute_list_url is None or self.add_attribute_url is None or self.authorization is None:
            self.logger.info("Event attribute and authorization is None")
        
    
    def search_add_event_attribute(self):
        try:
            headers = {
                        'Authorization': self.authorization,
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                        }
            response = requests.request("GET", self.event_attribute_list_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if "Event" in data:
                    event = data["Event"]
                    attribute = event["Attribute"]
                    if len(attribute) > 0:
                        for item in attribute:
                            value = item["value"]
                            self.attribute_events_values.append(value)
            self.logger.info("Existing Event (1512) attribute List Length - " + str(len(self.attribute_events_values)))
                            
        except Exception as e:
            self.logger.exception("Exception while listing the attribute for event" + str(e))
    
    def add_attribute_to_misp(self, highconfidence):
        attributes_to_add = set(highconfidence) - set(self.attribute_events_values)
        attributes_to_add = list(attributes_to_add)
        
        for item in attributes_to_add:
            # Hit Item to MISP add event
            self.add_event_attribute(item)
    
    def add_event_attribute(self, attribute_value):
        try:
            payload = json.dumps({
                    "event_id":"1512",
                    "value": attribute_value,
                    "category":"Network activity",
                    "type":"ip-src",
                    "comment" : "Added by automation"
                })
            headers = {
                        'Authorization': self.authorization,
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                        }
            response = requests.request("POST", self.add_attribute_url, headers=headers, data=payload)
            if response.status_code == 200:
                self.logger.info("Added attribute to event 1512 : " +  str(attribute_value))
                # If large number attributes to add, this time help to facilitate n/w error
                time.sleep(30)
        except Exception as e:
            self.logger.info("Exception occured while adding attributes to 1512" + str(e))