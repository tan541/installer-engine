# Application Engine on Endpoint

A cross-platform application installer engine which trigger by endpoint-agent
- MacOs >15
- Linux >13
- Window 11

## Architecture

There are two actors

1. Control plane: Backend service which generates tasks for agent to fetch based on org_id and task_status and target_platform and device_id and task_type and task_desc. E.g: {org_id: 1, target_platform: macos, device_id: 123, task_type: install.app, task_desc: ms_teams, task_status: new};
2. Endpoint Agent: local agent on device auto polling task and install app based on task detail

## Requirements

Task state:
- New: Control plane create task and not agent pickup yet
- Processing: Agent pick up the task and process
- Done: Agent finish install app and send status to control plan with successed
- Failed: Agent cannot finish the task with error

### Functional

- Generate tasks: Task is generated based on group_policy. E.g: {group_policy_id: 1, org_id: 1, group_type: distribute.app, app_name: teams}
- Fetch new tasks: Agent fetch new tasks from control plane
- Process tasks: Agent process task and install app
- Download app and verify:  Agent download app into local folder and check_sum the app
- Install app: install the app and report the status
- Sync process status: send process status to control plane

### Non-Functional

- Logging: add info log 
- Audit: store audit log into local file
