ARG PYTHON_VERSION=3.12.2-bookworm

# ----- base -----
FROM python:${PYTHON_VERSION} AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY ./Pipfile ./
RUN pip install pipenv && pipenv lock && pipenv requirements > requirements.txt
RUN rm -f ./Pipfile ./Pipfile.lock
RUN pip install --no-cache-dir --upgrade -r ./requirements.txt

# ----- idp -----
FROM base AS idp
WORKDIR /app/src
ENV PYTHONPATH=/app/src
COPY src/ /app/src/
CMD ["uvicorn", "idp.idp:app", "--host", "0.0.0.0", "--port", "8085"]

# ----- app -----
FROM base AS api
WORKDIR /app/src
ENV PYTHONPATH=/app/src
COPY src/ /app/src/
CMD ["uvicorn", "api.endpoints:app", "--host", "0.0.0.0", "--port", "8086"]

# ----- runner -----
FROM base AS runner
WORKDIR /app/src
ENV PYTHONPATH=/app/src
COPY src/ /app/src/
CMD ["uvicorn", "demo.endpoints:app", "--host", "0.0.0.0", "--port", "8087"]
