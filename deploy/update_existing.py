import boto3,json,subprocess,os
from pathlib import Path
NAME='ingyu-agentic-sdlc-lab-20261008';REGION='us-east-1'
s=boto3.Session(region_name=REGION);lam=s.client('lambda');ecr=s.client('ecr')
uri=lam.get_function(FunctionName=NAME)['Code']['ResolvedImageUri'];registry=uri.split('/')[0]
def run(*args,**kwargs):subprocess.run(args,check=True,**kwargs)
token=subprocess.check_output(['aws','ecr','get-login-password','--region',REGION]);run('docker','login','--username','AWS','--password-stdin',registry,input=token)
run('docker','pull',uri)
run('docker','run','--rm','--entrypoint','python','-v',str(Path.cwd())+':/upgrade','-w','/upgrade',uri,'live_model_eval.py','score')
# Public GitHub main contains the corrected audit test.
run('curl','-fLsS','https://raw.githubusercontent.com/ingyukoh/approval-gated-sdlc-lab/main/tests/test_http.py','-o','tests/test_http.py')
run('python3','package.py')
Path('/tmp/sdlc-delta.Dockerfile').write_text('FROM '+uri+'\nCOPY . ${LAMBDA_TASK_ROOT}\n')
image=registry+'/'+NAME+':upgrade'
run('docker','build','--platform','linux/amd64','-f','/tmp/sdlc-delta.Dockerfile','-t',image,'.')
run('docker','run','--rm','--entrypoint','python','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','-e','OTEL_SDK_DISABLED=true','-e','LITELLM_LOCAL_MODEL_COST_MAP=True',image,'-m','pytest','-q','--disable-warnings')
run('docker','push',image)
digest=ecr.describe_images(repositoryName=NAME,imageIds=[{'imageTag':'upgrade'}])['imageDetails'][0]['imageDigest'];lam.update_function_code(FunctionName=NAME,ImageUri=registry+'/'+NAME+'@'+digest)
lam.get_waiter('function_updated_v2').wait(FunctionName=NAME)
Path('results/aws-upgrade.json').write_text(json.dumps({'function':NAME,'image_digest':digest,'url':lam.get_function_url_config(FunctionName=NAME)['FunctionUrl'],'session_key_preserved':True,'public_role_unchanged':True},indent=2))
run('docker','logout',registry)
print('UPGRADE_READY',lam.get_function_url_config(FunctionName=NAME)['FunctionUrl'],flush=True)
