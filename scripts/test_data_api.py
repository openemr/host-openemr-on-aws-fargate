import boto3
import json

# Initialize AWS client for RDS Data API
rds_client = boto3.client("rds-data", region_name="us-east-1")

# Variables for RDS Data API
CLUSTER_ARN = ""
SECRET_ARN = ""

# Example use case
if __name__ == "__main__":
    sql_statement = ""
    response = rds_client.execute_statement(
        database='openemr',
        resourceArn=CLUSTER_ARN,
        secretArn=SECRET_ARN,
        sql=sql_statement
    )
    print(response)
