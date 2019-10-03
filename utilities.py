# coding=utf-8
"""
Utilities used within the VPN application.

It has been tested with MacOS Mojave.
"""

import ipaddress
import subprocess
import logging
import os

logger = logging.getLogger('Split_Tunnel')


def run_command(command, as_user_id=None):
    """
    Function for running a given command and return the output.

    :param command: Command which we want to run
    :type command: basestring
    :param as_user_id: The uid for the user we need to run the command for, example 501
    :type as_user_id: int
    """

    def change_user(user_uid):
        """Return a callable which sets the user to the correct user id."""

        def set_id():
            os.setuid(user_uid)

        return set_id

    if as_user_id:
        # If the user id is provided set the user before executing the command as preexec_fn
        set_user = change_user(int(as_user_id))

        # Run the given command
        process = subprocess.Popen(['bash', '-c', command],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   preexec_fn=set_user)
    else:
        # Run the given command
        process = subprocess.Popen(['bash', '-c', command],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
    process.wait()
    return process.stdout.read().decode(encoding="utf-8").rstrip('\n\r ')


class MacOSNetworkUtilsException(Exception):
    pass


class MacOSNetworkUtils:
    """
    Class containing all kind of utils to control the network settings on MacOS.
    """

    SUDO = '/usr/bin/sudo'
    IFCONFIG = '/sbin/ifconfig'
    IPCONFIG = '/usr/sbin/ipconfig'
    ROUTE = '/sbin/route'
    NETSTAT = '/usr/sbin/netstat'
    NDP = '/usr/sbin/ndp'
    ARP = '/usr/sbin/arp'
    NETWORKSETUP = '/usr/sbin/networksetup'

    @property
    def ipv4_routing_table(self):
        """
        Get the raw MacOS routing table, parse it, and return a nice dict.

        IPv6 routes should be excluded from the values, because we don't need them.

        :return: parsed_routing_table
        :rtype: dict
        """

        # Run the netstat command to get the IPv4 routes and remove the unneeded text
        try:
            raw_routing_table = run_command(f'{self.NETSTAT} -rn -f inet').splitlines()[4:]
            parsed_routing_table = [{'destination': destination.split()[0],
                                     'gateway': destination.split()[1],
                                     'interface': destination.split()[5]} for destination in raw_routing_table]
            return parsed_routing_table
        except IndexError:
            logger.error('Seems that something changed in the MacOS routing table. Please check the code and fix it!')
            exit(1)

    def parsed_routing_table(self):
        """
        Use the parsed IPv4 Routing table and present it as logging to the user.
        """
        routes = self.ipv4_routing_table

        display = '\nDestination         Gateway             Interface\n'
        for route in routes:
            destination = route.get('destination')
            gateway = route.get('gateway')
            interface = route.get('interface')

            display += f'{destination}{(20 - len(destination)) * " "}'
            display += f'{gateway}{(20 - len(gateway)) * " "}'
            display += f'{interface}\n'
        return display

    def set_default_route(self, interface='en0'):
        """
        Set the default route to a given interface.
        """
        # The interface is always needed
        if not interface:
            logger.error('Interface should be provided!')
            raise MacOSNetworkUtilsException()
        route_command = f'{self.SUDO} {self.ROUTE} change default -interface {interface}'
        result = run_command(route_command)
        if f'change net default: gateway {interface}' not in result:
            logger.error(f'Failed to change the default route: {result}')
            raise MacOSNetworkUtilsException()
        logger.debug(f'Default route set to interface: {interface}')

    def add_route(self, destination, gateway=None, interface=None):
        """
        Add a new route into the MacOS routing table.
        """
        if not gateway and not interface:
            logger.error('At least the interface or gateway should be provided!')
            raise MacOSNetworkUtilsException()
        elif not destination:
            logger.error('The destination should be provided!')
            raise MacOSNetworkUtilsException()

        route_command_extension = f'-interface {interface}' if interface else gateway
        add_route_command = f'{self.SUDO} {self.ROUTE} -n add {destination} {route_command_extension}'
        logger.info(f'Adding destination {destination}')
        logger.debug(f'Adding route with command: {add_route_command}')
        run_command(add_route_command)

    def delete_route(self, destination):
        """
        Delete a route from the MacOS routing table.
        """

        if not destination:
            logger.error('The destination should be provided!')
            raise MacOSNetworkUtilsException()
        logger.debug(f'Deleting {destination} from routing table...')
        run_command(f'{self.SUDO} {self.ROUTE} delete {destination}')

    def change_nameservers(self, nameservers, service='Wi-Fi'):
        """
        Change the current nameserver(s) in /etc/resolv.conf.

        It is allowed to provide 1 or more nameservers

        :param nameservers:
        :type: str or list
        :return:
        """

        if isinstance(nameservers, list):
            nameservers = ' '.join(nameservers)
        run_command(f'{self.SUDO} {self.NETWORKSETUP} -setdnsservers {service} {nameservers}')

    @property
    def current_nameservers(self, service='Wi-Fi'):
        """
        Get the current nameserver(s) by using networksetup.
        If there are no nameservers try the /etc/resolv.conf.

        :param service: The service which we should get the nameservers from
        :type: str

        :return: 1 or more nameservers
        :rtype: str or list
        """
        logger.debug('Getting the current nameservers...')
        nameservers = run_command(f'{self.SUDO} {self.NETWORKSETUP} -getdnsservers {service}')
        # If we are unable to get the dns we can alternatively get it with nslookup
        if "There aren't any DNS Servers set" in nameservers:
            result = run_command('cat /etc/resolv.conf').split('\n')
            nameservers = [line.split()[1] for line in result if 'nameserver' in line]
        return nameservers

    def current_router(self, interface):
        """
        Get the current default gateway and return it.

        :return: The default gateway
        :type: str
        """

        router = ''
        dhcp_info = run_command(f'{self.SUDO} {self.IPCONFIG} getpacket {interface}').splitlines()
        logger.debug(f'DHCP Information: {dhcp_info}')
        for line in dhcp_info:
            if 'router ' in line:
                router = line.split(':')[1].strip(' {}')
        logger.debug(f'Current router: {router}')
        return router

    @staticmethod
    def flush_routing_table():
        run_command("sudo ifconfig en0 down")
        run_command("sudo ifconfig en1 down")
        run_command("sudo route flush")
        run_command("sudo ifconfig en0 up")
        run_command("sudo ifconfig en1 up")
