# Configure the IKEv2 VPN
This step should be completed before running the application itself. The application uses the VPN interface to create a
connection and setup the routing table correctly.

Configure the VPN in the network settings and start it to be sure it could connect.

Go to "System Preferences" --> "Network" 
Click on the "+" icon and choose interface "VPN" with type "IKEv2"
Fill in the details and test the connection.


# Installation for VPN Application

## Install the VPN app:
`git@gitlab.com:maikelvallinga/vpn_split_tunnel.git`

Copy `config.ini.example` to `config.ini` and change your settings.

## Create Virtualenv: VPN

`mkvirtualenv -p /usr/local/bin/python3 vpn`

Install the pip packages from requirements.txt

`workon vpn`

`pip3 install -U -r requirements.txt`

## Copy Settings
Create a copy of the config.ini.example and name it config.ini. Then fill all missing details.

# Starting VPN
Starting the VPN could be done with a single command:
`source /Users/USERNAME/.virtualenvs/vpn/bin/activate && sudo python /Users/USERNAME/PATH_TO_PROJECT/vpn.py`

If the VPN is used a lot, it is better to make an alias for it.

### Networking

`netstat -rn` should show routes towards the VPN tunnel interface `ipsec<n>`


# Note: Mojave

For Mojave users it is important to add the terminal application as trusted.

- Go to the MacOS settings
- Open Security & Privacy
- Select Full Disk Access
- Add the application where you run the vpn from for example: iTerm2
