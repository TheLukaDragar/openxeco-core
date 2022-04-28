# Documentation to set up an openXeco instance

## Some links

https://docs.docker.com/engine/install/ubuntu/
https://ubuntu.com/tutorials/install-and-configure-apache#1-overview
https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-18-04
https://ubiq.co/tech-blog/enable-cors-apache-web-server/

https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=674857#25
https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=932458
https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=931899

## Prerequisite

### DNS configuration

The DNS should be configured to direct to the target machine. This is necessary to set up SSL configuration on Apache with 'Let's encrypt'. In our example:

```
XXX.XXX.XXX.XXX A  api.MYDOMAIN.XXX
XXX.XXX.XXX.XXX A  admin.MYDOMAIN.XXX
XXX.XXX.XXX.XXX A  community.MYDOMAIN.XXX
```

[MYDOMAIN.XXX] represents the domain you own for this instance

### Version selection

[v1.8.4] is an example of openXeco version for this documentation. Please see the other versions here:

https://github.com/CybersecurityLuxembourg/openxeco-core/releases

## Initialization of the setup

This procedure has been done on the following OS version:

```
> lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.1 LTS
Release:        20.04
Codename:       focal
```

### Update the package index

```
> sudo apt update
```

### Create directories for documents and images

```
> mkdir /image_folder
> mkdir /document_folder
```

## Docker

### Installation of Docker

```
> apt-get install docker.io
> snap install docker
```

For more information, see: https://docs.docker.com/get-docker/

### Run the MariaDB image

```
> docker run -p 3306:3306 -e MARIADB_ROOT_PASSWORD=E4syPass mariadb:10.7.3
```

The database and it structure will be created when the API will be correcly launched.

### Run the API image

```
> docker run -p 5000:5000 \
    -e ENVIRONMENT=prod \
    -e JWT_SECRET_KEY=my_secret_developer_key \
    -e DB_HOSTNAME=127.0.0.1 \
    -e DB_PORT=3306 \
    -e DB_NAME=OPENXECO \
    -e DB_USERNAME=root \
    -e DB_PASSWORD=E4syPass \
    -e MAIL_SERVER=127.0.0.1 \
    -e MAIL_PORT=1025 \
    -e MAIL_USE_TLS=False \
    -e MAIL_USE_SSL=False \
    -e MAIL_DEFAULT_SENDER=my-default-sender@MYDOMAIN.XXX \
    -e IMAGE_FOLDER=/image_folder \
    -e DOCUMENT_FOLDER=/document_folder \
    -e INITIAL_ADMIN_EMAIL=my-default-admin@MYDOMAIN.XXX \
    ghcr.io/cybersecurityluxembourg/openxeco-core-oxe-api:v1.8.4
```

### Build and run the webapps images

For the admin webapp:

```
> docker build \
    -f openxeco-core-oxe-web-admin-v1.8.4/Dockerfile
    -t oxe-web-admin-v1.8.4 \
    https://github.com/CybersecurityLuxembourg/openxeco-core/releases/download/v1.8.4/openxeco-core-oxe-web-admin-v1.8.4.tar.gz
> docker run -p 3000:3000 oxe-web-admin-v1.8.4
```

For the community webapp:

```
> docker build \
    -f openxeco-core-oxe-web-community-v1.8.4/Dockerfile
    -t oxe-web-community-v1.8.4 \
    https://github.com/CybersecurityLuxembourg/openxeco-core/releases/download/v1.8.4/openxeco-core-oxe-web-community-v1.8.4.tar.gz
> docker run -p 3001:3001 oxe-web-community-v1.8.4
```

## Apache server

### Install apache server

```
> sudo apt install apache2
> sudo a2enmod ssl
> sudo a2emod headers
> sudo mkdir /var/www/oxe-api
> sudo mkdir /var/www/oxe-web-admin
> sudo mkdir /var/www/oxe-web-community
```

### Create and init the configuration files

Let's configure the Apache server with:

```
cd /etc/apache2/sites-available/
sudo cp 000-default.conf oxe-api.conf
sudo cp 000-default.conf oxe-web-admin.conf
sudo cp 000-default.conf oxe-web-community.conf
```

You can edit oxe-api.conf as follow:

```
<VirtualHost *:80>
    ServerAdmin admin@MYDOMAIN.XXX
    ServerName api.MYDOMAIN.XXX
    DocumentRoot /var/www/oxe-api/
</VirtualHost>
```

You can edit oxe-web-admin.conf as follow:

```
<VirtualHost *:80>
    ServerAdmin admin@MYDOMAIN.XXX
    ServerName admin.MYDOMAIN.XXX
    DocumentRoot /var/www/oxe-web-admin/
</VirtualHost>
```

You can edit oxe-web-community.conf as follow:

```
<VirtualHost *:80>
    ServerAdmin admin@MYDOMAIN.XXX
    ServerName community.MYDOMAIN.XXX
    DocumentRoot /var/www/oxe-web-community/
</VirtualHost>
```

To take in count the new configuration, we need to run the following:

```
> sudo a2ensite oxe-api.conf
> sudo a2ensite oxe-web-admin.conf
> sudo a2ensite oxe-web-community.conf
> service apache2 reload
```

### Install 'Let's encrypt'

```
> #sudo add-apt-repository ppa:certbot/certbot # Not needed on recent versions of Ubuntu
> sudo apt install python3-certbot-apache
```

### Setup HTTPS virtual hosts

```
> sudo certbot --apache -d api.MYDOMAIN.XXX
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Plugins selected: Authenticator apache, Installer apache
Enter email address (used for urgent renewal and security notices) (Enter 'c' to
cancel): admin@MYDOMAIN.XXX

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Please read the Terms of Service at
https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf. You must
agree in order to register with the ACME server at
https://acme-v02.api.letsencrypt.org/directory
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(A)gree/(C)ancel: A

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Would you be willing to share your email address with the Electronic Frontier
Foundation, a founding partner of the Let's Encrypt project and the non-profit
organization that develops Certbot? We'd like to send you email about our work
encrypting the web, EFF news, campaigns, and ways to support digital freedom.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(Y)es/(N)o: N
Obtaining a new certificate
Performing the following challenges:
http-01 challenge for test-db.cy.lu
Enabled Apache rewrite module
Deploying Certificate to VirtualHost /etc/apache2/sites-available/oxe-api-le-ssl.conf
Enabling available site: /etc/apache2/sites-available/oxe-api-le-ssl.conf

Please choose whether or not to redirect HTTP traffic to HTTPS, removing HTTP access.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
1: No redirect - Make no further changes to the webserver configuration.
2: Redirect - Make all requests redirect to secure HTTPS access. Choose this for
new sites, or if you're confident your site works on HTTPS. You can undo this
change by editing your web server's configuration.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Select the appropriate number [1-2] then [enter] (press 'c' to cancel): 2
Enabled Apache rewrite module
Redirecting vhost in /etc/apache2/sites-enabled/oxe-api.conf to ssl vhost in /etc/apache2/sites-available/oxe-api-le-ssl.conf

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Congratulations! You have successfully enabled https://api.MYDOMAIN.XXX

You should test your configuration at:
https://www.ssllabs.com/ssltest/analyze.html?d=api.MYDOMAIN.XXX
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IMPORTANT NOTES:
 - Congratulations! Your certificate and chain have been saved at:
   /etc/letsencrypt/live/test-db.cy.lu/fullchain.pem
   Your key file has been saved at:
   /etc/letsencrypt/live/test-db.cy.lu/privkey.pem
   Your cert will expire on 2021-03-02. To obtain a new or tweaked
   version of this certificate in the future, simply run certbot again
   with the "certonly" option. To non-interactively renew *all* of
   your certificates, run "certbot renew"
 - If you like Certbot, please consider supporting our work by:

   Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
   Donating to EFF:                    https://eff.org/donate-le
```

Let's do this again for the oxe-web-admin and oxe-web-community virtual hosts

```
> sudo certbot --apache -d admin.MYDOMAIN.XXX
> sudo certbot --apache -d community.MYDOMAIN.XXX
```

### In case Apache is not starting

Here are a set a command that can be useful to track the error when Apache doesn't start properly

```
sudo apache2 -t -D DUMP_VHOSTS
sudo apache2ctl configtest
sudo journalctl | tail
sudo cat /var/log/apache2/error.log
```

### Configure the Apache virtual hosts



## All set !

The server is configured, we can finish with:

```
> sudo service apache2 restart
```