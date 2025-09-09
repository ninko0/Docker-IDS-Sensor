
                                          ### Change Subnet / gateway / Interface (parent) and the name if needed
## Create VLAN for HoneyPot. it did not affect IDS sensors. Only HoneyPot
sudo docker network create -d macvlan --subnet=192.168.69.0/24 --gateway=192.168.69.1 -o parent=eno1 opencanary69;

### Need If your arkime is not linked to a SIEM
# sudo docker-compose -f opensearch-docker/docker-compose.yml up -d;

sudo docker-compose -f suricata-docker/docker-compose.yml up -d;
sudo docker-compose -f zeek-docker/docker-compose.yml up -d;
sudo docker-compose -f opencanary-docker/docker-compose.yml up -d;
sudo docker-compose -f arkime-docker/docker-compose.yml up -d;

## INIT a user for arkime, without that, that's crash
sudo docker exec -it arkime-viewer /opt/arkime/bin/arkime_add_user.sh admin "Admin User" 'MonMotdepasse' --admin;
