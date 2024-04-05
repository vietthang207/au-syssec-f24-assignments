FROM python:3.8
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt
COPY server.py client.py shared_keys.py /app/
