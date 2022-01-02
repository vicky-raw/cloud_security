# cloud_security.
**alerts-fix.py**

Script to Fix Alerts automatically based on CSV sheet details which comes from Mvision/Panaseer, This Script is a Generic Version to achieve the end state.

There are more conditions that needs to be added to make it atleast better. As of now this Script contains conditions based on S3, SG, Loadbalancer, SQS. More conditions can be added as per the environment need, This will just serve as on higher level implementation using Mvision

There will be a sample CSV which contains details regarding the alerts which needs to be remeditated so that we can perform based on details from it(this will be added soon).

**emr_lambda.py**

This is the python code for the lambda function to do STS on Application accounts based on Event details.

 After doing STS, they can perform the operation on the resource(will be fetched from event details) as per the remediation needed to be done.

For more details: Please drop an email to Vikram.karingu@gmail.com
