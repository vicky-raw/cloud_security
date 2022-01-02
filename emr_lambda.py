#using this lambda ARN as target for default event bus in this account once created.
import boto3
import datetime
import json
from dateutil.tz import tzutc
import re
import time
import sys

def paginate(method, **kwargs):
      client = method.__self__
      paginator = client.get_paginator(method.__name__)
      for page in paginator.paginate(**kwargs).result_key_iters():
          for result in page:
              yield result

def convert_timestamp(item_date_object):
    if isinstance(item_date_object, (datetime.date, datetime.datetime)):
        return item_date_object.timestamp()
def del_alarm(cw_client,alarm):
  check_delete =  cw_client.delete_alarms(
        AlarmNames=[alarm,
        ]
    )
    
def run_it(event, context):
    ##List of cluster IDs
    print(event['account'])
    sts_connection = boto3.client('sts')
    role_name=f"arn:aws:iam::{event['account']}:role/{event['account']}-Developer-Role" #taking event data for account number from where event is coming
    acct_b = sts_connection.assume_role(
        RoleArn=role_name,
        RoleSessionName="cross_acct_lambda"
    )
    print(acct_b)
    ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
    SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
    SESSION_TOKEN = acct_b['Credentials']['SessionToken']
    emr_client = boto3.client('emr',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,)
    list_of_cluster_id = []
    alarm_names = []
    for response in paginate(emr_client.list_clusters, ClusterStates=['TERMINATED','TERMINATED_WITH_ERRORS']):
        final = json.dumps(response,default=convert_timestamp) 
        cluster_ids = list(set(re.findall(r"j-\w+",final)))
        list_of_cluster_id.append(cluster_ids)
    check_num=int(len(list_of_cluster_id))
    response1 = emr_client.describe_cluster(
        ClusterId=list_of_cluster_id[-1][0]
        )
    print("Check number: ",check_num)
    final = json.dumps(response1,default=convert_timestamp)
    a1 = str(final).split("CreationDateTime\":",1)[1]
    a1 = a1.split(", \"EndDateTime",1)[0]
    a1 = a1.replace(" ","")
    a1 = re.findall(r'[0-9]+.[0-9]+',a1)
    new_time = float(a1[0])
    print("New Time",new_time)
    max_alarm=50 #maximum no of alarms that can be there.
    while check_num<=max_alarm:
        for response in paginate(emr_client.list_clusters, ClusterStates=['TERMINATED','TERMINATED_WITH_ERRORS']):
            final = json.dumps(response,default=convert_timestamp) 
            cluster_ids = list(set(re.findall(r"j-\w+",final)))
            list_of_cluster_id.append(cluster_ids)
        check_num=int(len(list_of_cluster_id))
        response1 = emr_client.describe_cluster(
            ClusterId=list_of_cluster_id[-1][0]
        )
        final = json.dumps(response1,default=convert_timestamp)
        a1 = str(final).split("CreationDateTime\":",1)[1]
        a1 = a1.split(", \"EndDateTime",1)[0]
        a1 = a1.replace(" ","")
        a1 = re.findall(r'[0-9]+.[0-9]+',a1)
        new_time = float(a1[0])
    print("Cluster ID Count ",len(list_of_cluster_id),"/n",list_of_cluster_id)
    ### Delete Alarm_Names for selected clusters:
    cw_client = boto3.client('cloudwatch',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,)
    response = cw_client.describe_alarms(
        StateValue='INSUFFICIENT_DATA',
        AlarmNamePrefix='isEMRUsed',
    )
    ### Alarm names which needs to be deleted ### 
    for response in paginate(cw_client.describe_alarms, StateValue='INSUFFICIENT_DATA',AlarmNamePrefix='isEMRUsed'):
        final = json.dumps(response,default=convert_timestamp)
        alarm_name = list(set(re.findall(r'isEMRUsed[0-9]*_j-\w*',final)))
        alarm_names.append(alarm_name)
    print("Alarm Count ",len(alarm_names),"/n",alarm_names)
    alrm = 0
    flag=0
    flag1=0
    for alarm in alarm_names:
        for clust in list_of_cluster_id:
            if clust[0] in alarm[0]:
                print("entering for cluster and alarm", clust, alarm[0])
                try:
                    del_alarm(cw_client,alarm[0])
                    flag1=1
                    alrm = alrm +1
                except:
                    continue
            if flag1==0:
                flag=1
        if flag==1:
            response = cw_client.describe_alarms(AlarmNames=[alarm[0],])["MetricAlarms"][0]["StateUpdatedTimestamp"]
            final_time = json.dumps(response,default=convert_timestamp)
            print("final time",response)
            if float(final_time) < new_time:
                print("Deleting old and outdated alarm",alarm[0])
                try:
                    del_alarm(cw_client,alarm[0])
                    alrm = alrm +1
                except:
                    continue
    print(f'{alrm} are deleted') 
    
def lambda_handler(event, context):
    return run_it(event, context)
