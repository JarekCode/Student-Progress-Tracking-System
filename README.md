# Student-Progress-Tracking-System Installation Guide

## NGINX
Install NGINX using the commands found [here](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/#installing-a-prebuilt-debian-package-from-an-os-repository). (Steps 1 to 3)

## MongoDB
Install MongoDB using the commands found [here](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/#install-mongodb-community-edition). (Steps 1 to 4)
Run MongoDB using the commands found [here](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/#start-mongodb). (Steps 1 to 5)
**Note:** If you get any errors running MongoDB, [here](https://bobcares.com/blog/mongodb-exited-with-code-14/) are some solutions.

Once installed, create a new database using the following commands:

    mongo
    use fyp_db

Next, create the following 3 collections:

    db.createCollection("classes")
    db.createCollection("guides")
    db.createCollection("statistics")

Exit MongoDB.

## Application Code
Create a Student Progress Tracking System (SPTS) directory:

    sudo mkdir /opt/spts

Navigate to the project directory, initialise the Git repository and pull the code from GitHub.

    cd /opt/spts
    git init
    git pull https://github.com/jarek4477/Student-Progress-Tracking-System.git master

## uWSGI
The full Flask, uWSGI and NGINX setup guide can be found [here](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04). Short version below.
Recommended `sudo -i` to remove permission issues.

### Step 1 — Installing the Components
    sudo -i
    sudo apt update
    sudo apt install python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools

### Step 2 — Creating a Python Virtual Environment
    sudo apt install python3-venv

Inside the `/opt/spts` directory:

    cd /opt/spts
    sudo python3 -m venv projectEnv
    source projectEnv/bin/activate

### Step 3 — Setting Up a Flask Application
    pip install wheel
    pip install -r requirements.txt

### Create the SQLite Database
Inside the `/opt/spts` directory:

    python3

Type the following:

    from flaskApi import db
    from flaskApi.models import User
    
    db.create_all()

Exit Python3.

Check if the application works by using the following command:

    python3 /opt/spts/flaskApi.py

**Note:** If the application does not work due to an [error](https://github.com/rm-hull/luma.led_matrix/issues/154#issuecomment-397872953), you may have to run the following command depending on the error:

    sudo apt install libtiff5

### Step 4 — Creating a systemd Unit File
    sudo nano /etc/systemd/system/flaskApi.service

Write the following:

    [Unit]
    Description=uWSGI instance to serve production
    After=network.target
    
    [Service]
    User=ubuntu
    Group=www-data
    WorkingDirectory=/opt/spts
    Environment="PATH=/opt/spts/projectEnv/bin"
    ExecStart=/opt/spts/projectEnv/bin/uwsgi --ini flaskApi.ini
    
    [Install]
    WantedBy=multi-user.target

We can now start the uWSGI service we created and enable it so that it starts at boot:

Update Permissions

    chmod 777 /opt/spts
    chmod 777 /opt/spts/flaskApi

Continue:

    sudo systemctl start flaskApi
    sudo systemctl enable flaskApi

Check the status:

    sudo systemctl status flaskApi

### Step 5 — Configuring NGINX to Proxy Requests
    sudo nano /etc/nginx/sites-available/flaskApi

Write the following:

    server {
        listen 80;
        server_name your_domain www.your_domain;
        
        location / {
            include uwsgi_params;
            uwsgi_pass unix:/opt/spts/flaskApi.sock;
        }
    }

**Note:** Replace `your_domain` and `www.your_domain` above.
**Note:** For the line:

    server_name your_domain www.your_domain

you may also use your ip address for testing:

    server_name your_ip_address

Continue with the following commands:

    sudo ln -s /etc/nginx/sites-available/flaskApi /etc/nginx/sites-enabled
    sudo systemctl restart nginx
    sudo ufw allow 'Nginx Full'

Now visit `http://your_domain`

### Step 6 — Securing the Application
To secure the application using `certbot`, follow the steps [here](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04#step-7-%E2%80%94-securing-the-application).
