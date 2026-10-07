"""Creates only the tagged isolated demo. Authenticated CloudShell, not local creds."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import boto3

REGION = 'us-east-1'
NAME = 'ingyu-agentic-sdlc-lab-20261008'
ROLE = NAME + '-role'
SESSION = boto3.Session(region_name=REGION)
ACCOUNT = SESSION.client('sts').get_caller_identity()['Account']
TAG = {'Project': NAME, 'Purpose': 'isolated-public-fixture-demo'}
ecr = SESSION.client('ecr')
dynamo = SESSION.client('dynamodb')
iam = SESSION.client('iam')
lam = SESSION.client('lambda')
logs = SESSION.client('logs')


def run(*args, **kwargs):
    subprocess.run(list(args), check=True, **kwargs)


try:
    ecr.create_repository(repositoryName=NAME, imageScanningConfiguration={'scanOnPush': True},
                          tags=[{'Key': k, 'Value': v} for k, v in TAG.items()])
except ecr.exceptions.RepositoryAlreadyExistsException:
    pass
registry = f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com'
token = subprocess.check_output(['aws', 'ecr', 'get-login-password', '--region', REGION])
run('docker', 'login', '--username', 'AWS', '--password-stdin', registry, input=token)
image = registry + '/' + NAME + ':demo'
run('docker', 'build', '--platform', 'linux/amd64', '-t', image, '.')
run('docker', 'run', '--rm', '--entrypoint', 'python', image, '-m', 'pytest', '-q', '--disable-warnings')
run('docker', 'push', image)
image_digest = ecr.describe_images(repositoryName=NAME, imageIds=[{'imageTag': 'demo'}])['imageDetails'][0]['imageDigest']
uri = registry + '/' + NAME + '@' + image_digest
try:
    dynamo.create_table(TableName=NAME, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
      AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST',
      Tags=[{'Key': k, 'Value': v} for k, v in TAG.items()])
    dynamo.get_waiter('table_exists').wait(TableName=NAME)
    dynamo.update_time_to_live(TableName=NAME, TimeToLiveSpecification={'AttributeName': 'expires_at', 'Enabled': True})
except dynamo.exceptions.ResourceInUseException:
    pass
trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
try:
    iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{'Key': k, 'Value': v} for k, v in TAG.items()])
except iam.exceptions.EntityAlreadyExistsException:
    pass
role_arn = f'arn:aws:iam::{ACCOUNT}:role/{ROLE}'
policy = {'Version': '2012-10-17', 'Statement': [
  {'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
   'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{NAME}'},
  {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
   'Resource': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{NAME}:*'}]}
iam.put_role_policy(RoleName=ROLE, PolicyName='isolated-demo-state-and-logs', PolicyDocument=json.dumps(policy))
try:
    logs.create_log_group(logGroupName='/aws/lambda/' + NAME, tags=TAG)
except logs.exceptions.ResourceAlreadyExistsException:
    pass
logs.put_retention_policy(logGroupName='/aws/lambda/' + NAME, retentionInDays=7)
try:
    current = lam.get_function_configuration(FunctionName=NAME)
except lam.exceptions.ResourceNotFoundException:
    current = None
if current:
    lam.update_function_code(FunctionName=NAME, ImageUri=uri)
    lam.get_waiter('function_updated_v2').wait(FunctionName=NAME)
else:
    for attempt in range(12):
        try:
            lam.create_function(FunctionName=NAME, Role=role_arn, PackageType='Image',
              Code={'ImageUri': uri}, Architectures=['x86_64'], Timeout=30, MemorySize=1536,
              Environment={'Variables': {'STATE_TABLE': NAME, 'SESSION_KEY': secrets.token_hex(32),
                'OTEL_SDK_DISABLED': 'true', 'GUARDRAILS_PROCESS_COUNT': '1',
                'LANGCHAIN_TRACING_V2': 'false', 'LITELLM_LOCAL_MODEL_COST_MAP': 'True'}}, Tags=TAG)
            break
        except lam.exceptions.InvalidParameterValueException:
            if attempt == 11:
                raise
            time.sleep(5)
    lam.get_waiter('function_active_v2').wait(FunctionName=NAME)
lam.put_function_concurrency(FunctionName=NAME, ReservedConcurrentExecutions=3)
try:
    url = lam.create_function_url_config(FunctionName=NAME, AuthType='NONE')['FunctionUrl']
except lam.exceptions.ResourceConflictException:
    url = lam.get_function_url_config(FunctionName=NAME)['FunctionUrl']
for sid, action, extra in [('PublicFunctionURL', 'lambda:InvokeFunctionUrl', {'FunctionUrlAuthType': 'NONE'}),
                            ('PublicInvokeViaURL', 'lambda:InvokeFunction', {'InvokedViaFunctionUrl': True})]:
    try:
        lam.add_permission(FunctionName=NAME, StatementId=sid, Action=action, Principal='*', **extra)
    except lam.exceptions.ResourceConflictException:
        pass
state = {'name': NAME, 'region': REGION, 'role': ROLE, 'table': NAME, 'repository': NAME,
         'url': url, 'image_digest': image_digest, 'memory_mb': 1536, 'concurrency': 3,
         'deployed_utc_epoch': time.time(), 'iam_policy': policy}
Path('deployment-state.json').write_text(json.dumps(state, indent=2))
print('DEPLOYMENT_READY ' + json.dumps({k: state[k] for k in ('url', 'name', 'image_digest')}))
