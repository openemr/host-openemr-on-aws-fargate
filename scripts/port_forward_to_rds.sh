#!/bin/bash

# Check if the cluster name and host were provided as arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <cluster-name> <host>"
  exit 1
fi

# Set the cluster name from the first argument
CLUSTER_NAME="$1"

# Set the host name from the second argument
HOST="$2"

# Default MySQL port (3306)
PORT="3306"

# Use aws ecs list-tasks to get task ARNs and parse the output
task_arns=$(aws ecs list-tasks --cluster "$CLUSTER_NAME" --query "taskArns" --output text)

# Convert the space-separated task ARNs into an array
task_arn_array=($task_arns)

# Get the length of the array
num_tasks=${#task_arn_array[@]}

# Generate a random index between 0 and num_tasks - 1
random_index=$((RANDOM % num_tasks))

# Select the task ARN at the random index
random_task_arn=${task_arn_array[$random_index]}

# Get runtime ID and append "ecs:" to it to make target string
runtime_id=$(aws ecs describe-tasks --cluster "$CLUSTER_NAME" --tasks "$random_task_arn" \
    --query "tasks[0].containers[0].runtimeId")

# Remove quotes from runtime ID
runtime_id="${runtime_id%\"}"
runtime_id="${runtime_id#\"}"

# Get task ID
task_id=$(echo ${runtime_id} | cut -d '-' -f 1)

echo $task_id

# Generate target string
TARGET="ecs:"
TARGET+=""
TARGET+=$CLUSTER_NAME
TARGET+="_"
TARGET+=$task_id
TARGET+="_"
TARGET+=$runtime_id

# Generate parameter string
parameters=\'
parameters+='{"host":['
parameters+=$HOST
parameters+='],"portNumber":['
parameters+=$PORT
parameters+='],"localPortNumber":['
parameters+=$PORT
parameters+=']}'

echo "Starting SSM session on host $HOST with target $TARGET and port $PORT..."

# Start an SSM session on the specified target with port forwarding

parameters="host=$HOST,portNumber=$PORT,localPortNumber=$PORT"

aws ssm start-session --target "$TARGET" \
  --document-name "AWS-StartPortForwardingSessionToRemoteHost" \
  --parameters "$parameters"