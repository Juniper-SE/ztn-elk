
FROM python:3.8
RUN apt-get update
RUN apt-get -y install gcc
RUN mkdir /usr/src/app
WORKDIR /usr/src/app
COPY ./requirements.txt .
RUN pip install -r requirements.txt
COPY . .
WORKDIR /usr/src/app/ztn
EXPOSE 9999
CMD ["python3", "app.py"]
