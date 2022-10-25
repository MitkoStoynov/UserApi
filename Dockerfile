FROM python:3.9.13-buster

#RUN apt-get update && apt-get install -y python3 python3-pip

#RUN sudo docker ps -aqf "name=flaskapp:1.0"
#ADD /home/mitko/jwtRSA256-private.pem .
#ADD jwtRSA256-public.pem /app/

WORKDIR /app

COPY . /app

RUN pip3.9 --no-cache-dir install -r requirements.txt
RUN pip3.9 install mysql-connector-python
RUN pip3.9 install mysqlclient

EXPOSE 5000

ENTRYPOINT ["python3"]
CMD ["app.py"]
