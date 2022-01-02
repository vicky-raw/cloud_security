import csv
import boto3
import argparse

def assume_role_creds(region, role_name):
    sts_connection = boto3.client('sts', region_name=region)
    try:
        acct_b = sts_connection.assume_role(
            RoleArn=role_name,
            RoleSessionName="Security-Alerts"
        )
        session= boto3.Session(aws_access_key_id=acct_b['Credentials']['AccessKeyId'],
                aws_secret_access_key=acct_b['Credentials']['SecretAccessKey'],
                aws_session_token=acct_b['Credentials']['SessionToken']) 
        return session
    except:
        print("Error while assuming role",role_name)
        with open("unassumed_roles.txt",'a+') as f:
                f.write(role_name)

def process_alerts(temp_session,line):
    sg_alert_configs = ["AWS Security groups allow internet traffic", "AWS Security Group allows all traffic", "Security Groups should not have unrestricted"]

    if any(x.lower() in line['Config Setting Name'].lower() for x in sg_alert_configs):
        ec2_client=temp_session.client('ec2',region_name="us-east-1")
        try:
            sg_data = ec2_client.describe_security_group_rules(
            Filters=[
            {
                'Name': 'group-id',
                'Values': [
                    line['Resource Id'],
                ]
            },
            ]
            )
            for sg_rule in sg_data['SecurityGroupRules']:
                if sg_rule['IsEgress'] == False and  sg_rule['CidrIpv4']== '0.0.0.0/0':
                    from_port = sg_rule['FromPort']
                    to_port  = sg_rule['ToPort']
                    ip_protocol=sg_rule['IpProtocol']
                    try:
                        ec2_client.authorize_security_group_ingress(
                        GroupId= line['Resource Id'],
                        IpPermissions=[
                        {'IpProtocol': ip_protocol, 
                        'FromPort': from_port, 
                        'ToPort': to_port, 
                        'IpRanges': [
                                {
                                    'CidrIp': '10.0.0.0/8'
                                },
                                {
                                    'CidrIp': '192.168.0.0/16'
                                }
                            ]}
                            ])
                    except:
                        print("Error while adding sg rule")
                    try:
                        ec2_client.revoke_security_group_ingress(
                        GroupId= line['Resource Id'],
                        IpPermissions=[
                        {'IpProtocol': ip_protocol, 
                        'FromPort': from_port, 
                        'ToPort': to_port, 
                        'IpRanges': [
                                {
                                    'CidrIp': '0.0.0.0/0'
                                },
                            ]}
                            ])
                        with open('fixed_output.csv', mode='a+',newline='') as out:
                            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                            line['Status']="Fixed"
                            out_write.writerow([line])
                    except:
                        print("error while removing CIDR range from SG")

        except Exception as e:
                print("Error while describing SG rules , SG might/not exist")
                with open('security_error_log.csv', mode='a+',newline='') as out:
                    out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    line['Status']="Failed/NotFound"
                    out_write.writerow([line])

    if "AWS Default Security Group does not restrict all traffic" in line['Config Setting Name']:
       #have this code logic ready, will be adding soon.
        None
    if ("Access logging should be enabled for S3 bucket".lower() in line['Config Setting Name'].lower() or "S3 buckets should not be unencrypted".lower() in line['Config Setting Name'].lower()) :
        s3_client=temp_session.client('s3',region_name="us-east-1")
        log_bucket_name =""
        if "Access logging should be enabled for S3 bucket" in line['Config Setting Name'] :
            for bucket in s3_client.list_buckets()["Buckets"]:
                try:
                    region_bucket= s3_client.head_bucket(Bucket=bucket['Name'])
                    if region_bucket['ResponseMetadata']['HTTPHeaders']['x-amz-bucket-region'] == 'us-east-1':
                        if ("logs" or "log") in bucket['Name'] and "emr" not in bucket['Name']:
                            log_bucket_name = bucket['Name']
                            break 
                except Exception as e:
                    print("error while getting bucket details- Access issue")
                    continue
            print("Log bucket name is",log_bucket_name)
            try:
                s3_client.put_bucket_logging(
                Bucket=line['Resource Id'],
                BucketLoggingStatus= {
                    'LoggingEnabled': {
                        'TargetBucket': log_bucket_name,
                        'TargetPrefix': "/"
                    }
                })
                with open('fixed_output.csv', mode='a+',newline='') as out:
                            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                            line['Status']="Fixed"
                            out_write.writerow([line])
            except Exception as e:
                print("Bucket is in other region rather than us-east-1")
                with open('security_error_log.csv', mode='a+',newline='') as out:
                    out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    line['Status']="Failed/NotFound"
                    out_write.writerow([line])
        else:
            try:
                s3_client.put_bucket_encryption(
                    Bucket=line['Resource Id'],
                    ServerSideEncryptionConfiguration={
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                }
                            }
                        ]
                    }
                    )
                with open('fixed_output.csv', mode='a+',newline='') as out:
                            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                            line['Status']="Fixed"
                            out_write.writerow([line])
            except Exception as e:
                print("Error while adding bucket encryption")
                with open('security_error_log.csv', mode='a+',newline='') as out:
                    out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    line['Status']="Failed/NotFound"
                    out_write.writerow([line])
    if "WS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled".lower() in line['Config Setting Name'].lower():
            ec2_client=temp_session.client('ec2')
            log_bucket_name =""
            s3_client=temp_session.client('s3',region_name="us-east-1")
            try:
                for bucket in s3_client.list_buckets()["Buckets"]:
                    region_bucket= s3_client.head_bucket(Bucket=bucket['Name'])
                    try:
                        region_bucket= s3_client.head_bucket(Bucket=bucket['Name'])
                        if region_bucket['ResponseMetadata']['HTTPHeaders']['x-amz-bucket-region'] == 'us-east-1':
                            if ("logs" or "log") in bucket['Name'] and "emr" not in bucket['Name']:
                                log_bucket_name = bucket['Name']
                                break 
                    except Exception as e:
                        print("error while getting bucket details- Access issue")
                        continue   
                ec2_client.modify_load_balancer_attributes(
                LoadBalancerName=line['Resource Id'],
                LoadBalancerAttributes={
                    'AccessLog': {
                        'Enabled': True,
                        'S3BucketName': log_bucket_name,
                        'S3BucketPrefix': 'access_log'
                    },
                }
                )
                with open('fixed_output.csv', mode='a+',newline='') as out:
                            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                            line['Status']="Fixed"
                            out_write.writerow([line])
            except Exception as e:
                print("Error configuring ALB logging")
                with open('security_error_log.csv', mode='a+',newline='') as out:
                    line['Status']="Failed/NotFound"
                    out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    out_write.writerow([line])

    if "AWS SQS server side encryption not enabled" in line['Config Setting Name']:
        sqs_client=temp_session.client('sqs',region_name="us-east-1")
        try:
            sqs_client.set_queue_attributes(
                    QueueUrl=line['Resource Id'],
                    Attributes={
                        'KmsMasterKeyId': 'alias/aws/sqs'
                    }
                )
            with open('fixed_output.csv', mode='a+',newline='') as out:
                            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                            line['Status']="Fixed"
                            out_write.writerow([line])
        except Exception as e:
            with open('security_error_log.csv', mode='a+',newline='') as out:
                out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                line['Status']="Failed/NotFound"
                out_write.writerow([line])
    else:
        with open('untouched_alerts.csv', mode='a+',newline='') as out:
            out_write  = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            line['Status']="Untouched"
            out_write.writerow([line])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read Inputs given to update SSM parameter values',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--csvfile', required=True,
                        help='Pass CSV file from panaseer alerts dashboard')
    args = parser.parse_args()
    with open(args.csvfile, 'r', newline='') as f_input:
        csv_input = csv.DictReader(f_input)
        data = sorted(csv_input, key=lambda row: (row['Cloud Account ID']))

    with open('output1.csv', 'w', newline='') as f_output:    
        csv_output = csv.DictWriter(f_output, fieldnames=csv_input.fieldnames)
        csv_output.writeheader()
        csv_output.writerows(data)
        
    with open('output1.csv', 'r', newline='') as f_input:
        csv_input = csv.DictReader(f_input)
        headers = csv_input.fieldnames
        prev_account=0
        for index,line in enumerate(csv_input):
            print(index)
            if line['Cloud Account ID'].isdecimal():
                if len(line['Cloud Account ID'])<12:
                    account_no= "0"*(12-len(line['Cloud Account ID']))+line['Cloud Account ID']
                else:
                    account_no = line['Cloud Account ID']
                print(line['Cloud Account ID'], line['Config Setting Name'])
                print("Running on Resource ID",line['Resource Id'])
                if index==0 or prev_account!=account_no:
                    print("changing session")
                    temp_session=assume_role_creds("us-east-1", f"arn:aws:iam::{account_no}:role/{account_no}-Admin-Role")
                if temp_session!=None:
                    process_alerts(temp_session,line)
                prev_account=line['Cloud Account ID']
