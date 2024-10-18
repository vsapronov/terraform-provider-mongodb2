# Terraform Provider Mongodb

This repository is a Terraform Mongodb for [Terraform](https://www.terraform.io).

### Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 0.13
- [Go](https://golang.org/doc/install) >= 1.17

### Installation

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the `make install` command:

````bash
git clone https://github.com/vsapronov/terraform-provider-mongodb2
cd terraform-provider-mongodb2
make install
````

### To test locally 

**1.1: create mongo image  with ssl**


````bash
cd docker/docker-mongo-ssl
docker build -t mongo-local .
````
**1.2: create ssl for localhost**


*follow the instruction in this link*

https://ritesh-yadav.github.io/tech/getting-valid-ssl-certificate-for-localhost-from-letsencrypt/


````bash
nano /etc/hosts
127.0.0.1   kaginar.herokuapp.com   ### add this line 
````


**1.3: start the docker-compose**
````bash
cd docker
docker-compose up -d
````
**1.4 : create admin user in mongo**

````bash
$ docker exec -it mongo -c mongo
> use admin
> db.createUser({ user: "root" , pwd: "root", roles: ["userAdminAnyDatabase", "dbAdminAnyDatabase", "readWriteAnyDatabase"]})
````
**2: Build the provider**

follow the [Installation](#Installation)

**3: Use the provider**

````bash
cd mongodb
make apply
````
