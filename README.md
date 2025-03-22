### Network Operation Center (noc)

# Instalation
- run `pip install -r requirements.txt`

# Firewall
- Ubuntu (ufw) `sudo ufw allow 1983/tcp`
- Other (firewalld) `sudo firewall-cmd --zone=public --add-port=1983/tcp --permanent` and `sudo firewall-cmd --reload`