FROM ubuntu:bionic
RUN apt-get update
RUN apt-get install -y apt-utils vim curl apache2 apache2-utils
RUN apt-get -y install python3 libapache2-mod-wsgi-py3
RUN ln /usr/bin/python3 /usr/bin/python
RUN apt-get -y install python3-pip
RUN ln /usr/bin/pip3 /usr/bin/pip
RUN pip install --upgrade pip
RUN pip install django ptvsd && pip install requests
RUN apt-get install -y -q --allow-downgrades \ 
    python3-protobuf
    
EXPOSE 80 3500
CMD ["apache2ctl", "-D", "FOREGROUND"]