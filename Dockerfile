FROM centos:8

COPY flask_labris/ansible-playbook.yml /opt/
COPY flask_labris/inventory /opt/

RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo

RUN yum install -y python3 && yum install -y python3-pip && pip3 install --upgrade pip && pip install ansible

WORKDIR /opt/
RUN ansible-playbook ansible-playbook.yml

EXPOSE 5000 443 80

CMD ["sh", "-c", "su -c \"pg_ctl -D /var/lib/pgsql/data -l /var/lib/pgsql/data/logfile start\" - postgres && cd /opt/flask_labris && nginx && nginx -s reload && uwsgi --socket 0.0.0.0:5000 --protocol=http -w wsgi:app"]