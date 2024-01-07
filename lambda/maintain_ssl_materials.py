import boto3
import os

def handler(event, context):

    #Create ECS client
    ecs_client = boto3.client('ecs')

    #Get environment variables
    cluster = os.environ['ECS_CLUSTER']
    task_definition = os.environ['TASK_DEFINITION']
    security_groups = os.environ['SECURITY_GROUPS'].split(',')
    subnets = os.environ['SUBNETS'].split(',')

    #Run ECS task
    response = ecs_client.run_task(
        cluster=cluster,
        launchType='FARGATE',
        taskDefinition=task_definition,
        count=1,
        networkConfiguration={
            'awsvpcConfiguration': {
                'securityGroups': security_groups,
                'subnets': subnets
            }
        }
    )

    #Get TaskARN
    task_arn = response["tasks"][0]['taskArn']

    #Wait for task to stop
    tasks_stopped_waiter = ecs_client.get_waiter('tasks_stopped')
    tasks_stopped_waiter.wait(
        cluster=cluster,
        tasks=[task_arn]
    )

    #Return success code
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }