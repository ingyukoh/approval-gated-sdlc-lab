FROM public.ecr.aws/lambda/python:3.12
ENV OTEL_SDK_DISABLED=true GUARDRAILS_PROCESS_COUNT=1 LANGCHAIN_TRACING_V2=false LITELLM_LOCAL_MODEL_COST_MAP=True PYTHONDONTWRITEBYTECODE=1
COPY requirements.lock ${LAMBDA_TASK_ROOT}/requirements.lock
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.lock
COPY . ${LAMBDA_TASK_ROOT}/
CMD ["app.handler"]
