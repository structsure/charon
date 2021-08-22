FROM python:3

RUN apt-get -y update && apt-get install -y vim

RUN mkdir /eve
WORKDIR /eve

ADD requirements.txt /eve/
RUN pip install --no-cache-dir -r requirements.txt

COPY src /eve/src
WORKDIR /eve/src

EXPOSE 5000

CMD ["gunicorn", "--workers", "2", \
    "--bind", "0.0.0.0:5000", \
    "--error-logfile", "-", \ 
    "--access-logfile", "-", \
    "--log-level", "info", \
    "--timeout", "900", \
    "run:app"]
