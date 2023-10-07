#use amd64 image



FROM --platform=linux/amd64 python:3.8-slim-buster

ENV PYTHONUNBUFFERED=1

ARG ENVIRONMENT=dev

WORKDIR /usr/app

RUN echo "ENVIRONMENT: $ENVIRONMENT"
RUN echo "PYTHON VERSION: $PYTHON_VERSION"

RUN pip install gunicorn[gevent]

COPY oxe-api/.docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
#print  statsus
RUN echo "ENVIRONMENT: $ENVIRONMENT"
#PRINT PYTHON VERSION
RUN python --version
#PRINT PIP VERSIO

COPY oxe-api/requirements.txt requirements.txt
RUN pip install -r requirements.txt

CMD /entrypoint.sh
