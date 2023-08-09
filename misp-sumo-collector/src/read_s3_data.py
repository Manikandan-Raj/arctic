import sys
import botocore
import boto3
import pandas as pd
import io
import misp
import logging
import os
import threading
import add_attribute


class ReadS3Data:
    def __init__(self, logger):
        self.logger = logger
        self.load_env_variables()
        self.connect_to_s3()
        self.misp = misp.MISP(self.logger)
        self.add_attribute = add_attribute.AddAttribute(logger)
        self.guardDuty = []
        self.cortex = []
        self.highConfidence = []
        self.route53 = []
        self.csall = []
        self.high_confidence_ips = []
        self.other_confidence_ips = []
        self.thread_list = []
        self.route_53_csv_file_count = 0

    def load_env_variables(self):
        self.s3_bucket_name = str(os.environ["S3_BUCKET_NAME"])
        if self.s3_bucket_name is None:
            self.logger.info("S3 Bucket name needs to be passed. can't proceed further")

    def connect_to_s3(self):
        try:
            client_config = botocore.config.Config(max_pool_connections=1000, read_timeout=900, connect_timeout=900,
                                                   retries={'max_attempts': 3}, )
            self.s3_object = boto3.client('s3', config=client_config)
        except Exception as e:
            self.logger.exception("Exception while initiating the object for s3" + str(e))
            sys.exit(1)

    def get_object_data(self, object_key, column,columnname, file_type=".gz", column_list=None):
        try:
            object_response = self.s3_object.get_object(Bucket=self.s3_bucket_name, Key=object_key)
            if file_type == ".gz":
                csv_file_data = pd.read_csv(io.BytesIO(object_response['Body'].read()), compression='gzip')
            else:
                csv_file_data = pd.read_csv(io.BytesIO(object_response['Body'].read()))

            column_value = list(csv_file_data[column])
            if columnname == "CS_All":
                confidence = list(csv_file_data["malicious_confidence"])
                self.process_cs_all_data(column_value, confidence, column_list)
            
            else:
                while len(column_value) >= 200:
                    process_data = column_value[:200]
                    process_data = list(set(process_data))
                    column_list.extend(process_data)
                    column_value = column_value[200:]
                if len(column_value) > 0:
                    column_value = list(set(column_value))
                    column_list.extend(column_value)

        except Exception as e:
            self.logger.info("S3 Object Name..."+str(e))
    
    def process_cs_all_data(self, column_value, confidence, column_list):
        
        while len(column_value) >= 200:
                process_data = column_value[:200]
                process_data = list(set(process_data))
                
                process_confidence_data = confidence[:200]
                process_confidence_data = list(set(process_confidence_data))
                
                result = zip(process_data, process_confidence_data)
                column_list.append(dict(result))
                
                column_value = column_value[200:]
                
                confidence = confidence[200:]
        if len(column_value) > 0:
            column_value = list(set(column_value))
            
            confidence = list(set(confidence))
            
            result = zip(column_value, confidence)
            column_list.append(dict(result))
        
            
    def read_s3_data(self, prefix=None, column=None, columnname=None, column_list=None):
    
        paginator = self.s3_object.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=self.s3_bucket_name, Prefix=prefix)

        for page in pages:
            for item in page['Contents']:
                s3_object_key = item["Key"]
                self.logger.info("Second s3 object key with csv file: " + str(s3_object_key))
                if s3_object_key.endswith(".gz") or s3_object_key.endswith(".csv"):
                    if column == "query_name":
                        self.route_53_csv_file_count += 1
                    file_type = ".gz" if s3_object_key.endswith(".gz") else ".csv"
                    thread = threading.Thread(target=self.get_object_data,
                                              args=(s3_object_key, column,columnname, file_type, column_list))
                    thread.start()
                    self.thread_list.append(thread)
                    

        for thread in self.thread_list:
            thread.join()
            
    def iterate_bucket_folder(self):
        folder = ['GuardDuty','Cortex','HighConfidence', 'Route53', "CS_All"]
        column_specific = {
            "GuardDuty": "domain",
            "Cortex": 'ioc',
            "HighConfidence": "clientip",
            "Route53": "query_name",
            "CS_All" : "clientip"
        }

        column_specific_value = {
            "GuardDuty": self.guardDuty,
            "Cortex": self.cortex,
            "HighConfidence": self.highConfidence,
            "Route53": self.route53,
            "CS_All" : self.csall
        }
        for item in folder:
            response = self.s3_object.list_objects(Bucket=self.s3_bucket_name, Prefix="Sumo_for_MISP/" + item + "/",
                                                   Delimiter="/")
            if "CommonPrefixes" in response:
                common_prefixes = response["CommonPrefixes"]
                prefix_value = common_prefixes.pop()
                self.logger.info("First s3 object key: " + str(prefix_value))
                prefix_name = prefix_value['Prefix']
                self.read_s3_data(prefix=prefix_name, column=column_specific[item],columnname=item,
                                  column_list=column_specific_value[item])

        self.guardDuty = set(self.guardDuty)
        self.cortex = set(self.cortex)
        self.highConfidence = set(self.highConfidence)
        self.route53 = set(self.route53)
        
        self.logger.info("Length of the GuardDuty.. " + str(len(self.guardDuty)))
        self.logger.info("Length of the Cortex.. " + str(len(self.cortex)))
        self.logger.info("Length of the HighConfidence.. " + str(len(self.highConfidence)))
        self.logger.info("Length of the Route 53.. " + str(len(self.route53)))
        
        self.seperate_ip_on_confidence()
        self.logger.info("Length of the CS Attribute with high confidence.. " + str(len(self.high_confidence_ips)))
        self.logger.info("Length of the CS Attribute with other than high confidence.. " + str(len(self.other_confidence_ips)))

        self.add_attribute.search_add_event_attribute()
        self.add_attribute.add_attribute_to_misp(self.highConfidence)
        
        self.connect_to_misp()

    def connect_to_misp(self):
        all_data_list = [{"GuardDuty": self.guardDuty},
                         {"Cortex": self.cortex},
                         {"Route53": self.route53},
                         {"CS_ALL_HIGH" : self.high_confidence_ips},
                         {"CS_ALL_Other_Than_High": self.other_confidence_ips}]
        for data_process in all_data_list:
            for name, value in data_process.items():
                value = list(value)
                while len(value) >= 200:
                    process_data = value[:200]
                    self.misp.search_attribute(name, process_data)
                    value = value[200:]
                if len(value) > 0:
                    self.misp.search_attribute(name, value)
    
    def seperate_ip_on_confidence(self):
        
        
        for item in self.csall:
            # Updating the high confidence and other confidence values
            [self.high_confidence_ips.append(k) if v == 'high' else self.other_confidence_ips.append(k) for k,v in item.items()]
        
        self.high_confidence_ips = set(self.high_confidence_ips)
        self.other_confidence_ips = set(self.other_confidence_ips)
        


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger("thread-intel-misp-sumo-collector")
    start_obj = ReadS3Data(logger)
    start_obj.iterate_bucket_folder()