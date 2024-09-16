# Labris-flask
Designed and deployed a dynamic Flask web application using uWSGI and Nginx, secured with ModSecurity, containerized, ansible was used to automate the configuration, and served over HTTPS using Nginx with ModSecurity for enhanced security.

Pull image:

```
docker pull usersefa/centos-nginx-ansible
```

Run on Linux/Ubuntu:

```
docker run -d usersefa/centos-nginx-ansible
```

on Windows:

```
docker run -d -p 443:443 -p 5000:5000 -p 80:80 usersefa/centos-nginx-ansible
```

Go to ``` https://localhost ``` on windows or on linux ```https://172.17.0.2```


## Serve Flask Application using uWSGI and Nginx

- Activate environment:
```
source venv/bin/activate
pip install -r requirements.txt
```

```sudo ufw allow 5000```

- Test manually: ``` python myproject.py ```

- Creating the WSGI Entry Point

```
nano ~/flaskProject/wsgi.py
```
```
from myproject import app

if __name__ == "__main__":
    app.run()
```

- Configuring uWSGI
```
uwsgi --socket 0.0.0.0:5000 --protocol=http -w wsgi:app
http://127.0.0.1:5000
```

- Creating a uWSGI Configuration File ``` nano ~/flaskProject/myproject.ini ```
```
[uwsgi]
module = app:app

master = true
processes = 5

socket = myproject.sock
chmod-socket = 660
vacuum = true

die-on-term = true
```

```sudo systemctl start myproject```

```sudo systemctl enable myproject```

Check Status ```sudo systemctl status myproject```

- Configuring Nginx to Proxy Requests
```
sudo nano /etc/nginx/sites-available/myproject
```

```
server {
    listen 80;
    server_name localhost;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/home/sefacs/PycharmProjects/flaskProject/myproject.sock;
    }
}
```

```sudo ln -s /etc/nginx/sites-available/myproject /etc/nginx/sites-enabled```

```sudo nginx -t```

```sudo systemctl restart nginx```

```sudo ufw delete allow 5000```

```sudo ufw allow 'Nginx Full'```

Configure ```sudo nano /etc/systemd/system/myproject.service```

```
[Unit]
Description=uWSGI instance to serve myproject
After=network.target

[Service]
User=sefacs
Group=www-data
WorkingDirectory=/home/sefacs/PycharmProjects/flaskProject
Environment="PATH=/home/sefacs/PycharmProjects/flaskProject/venv/bin"
ExecStart=/home/sefacs/PycharmProjects/flaskProject/venv/bin/uwsgi --ini myproject.ini

[Install]
WantedBy=multi-user.target
```

Give the permissions:
```
sudo chmod -R 755 /home/sefacs/PycharmProjects/flaskProject
sudo chmod 777 myproject.sock
```

```
sudo systemctl restart myproject
```

You should now be able to navigate to your server’s domain name in your web browser: ```http://localhost```


![flask1](https://github.com/user-attachments/assets/4910f132-9098-44e0-b556-b02ceeef4dcc)

![flask2](https://github.com/user-attachments/assets/c8ec5eb7-2250-4a73-85a1-e6bdf9b2f506)

![flask3](https://github.com/user-attachments/assets/48c9c386-45b9-40cb-8fbd-7584e27a274e)

![flask4](https://github.com/user-attachments/assets/f7c57dfa-602c-467c-8925-16987428ece8)





