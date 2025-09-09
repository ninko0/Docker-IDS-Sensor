# What is this project ?

### It's just a fast deployment of IDS sensor, packet captur and HoneyPot in docker
### It's based on Suricata , Zeek for IDS / Arkime for packet captur / Opencanary for honeyPot

##### I did a start script because it is easier for me but you can just use docker-compose for eatch files.

---
# You Need to change some of the conf files. Here is a list you need to check
## Start script
#### macvlan :
- subnet 
- gateway
- parent (interface)
- name (if needed)
## Zeek
#### Interfaces in zeek-docker/docker-compose.yml
#### IP in zeek-docker/scripts/canary.zeek
## Suricata
#### Interfaces suricata-docker/docker-compose.yml
#### change IP in local.rules
## Canary
#### Names :

- Both container in docker-compose
- Both node in .opencanary.conf

###### I have my own naming system , you can choose what ever you want
#### Network  / IP address
## Arkime
### Arkime is more complicated. It need a SIEM, it can be ELK (especialy Elasticsearch for the DataBase ) or Opensearch. For this POC i used Opensearch on my local host.
### Arkime work with 3 containers :
- #### Arkime INIT it just start initialise some parameters then exit
- #### Arkime viewer the web Interface
- #### Arkime Capture capture on interfaces

### Things you need to change :

#### Elasticsearch / Opensearch URL in docker-compose and in both config.ini
#### Interfaces in both config.ini 
#### Arkime Capture node name (last ligne of docker-compose.yml)
---

## Nothing is here to be "turnkey" , you need a minimum of knowledge in docker and on all the solutions you are using. The project is here to help and have a faster deployment.
