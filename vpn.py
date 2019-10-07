# coding=utf-8
"""
Script to start a split-tunnel VPN.
"""

import configparser
import itertools
import logging
import os
import pync
import signal
import sys

from datetime import datetime
from time import sleep, time
from utilities import MacOSUtils


config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.ini'))

DEBUG = config['GENERAL'].getboolean('debug')

logger = logging.getLogger('VPN')
if DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

log_file = logging.FileHandler(config['GENERAL']['log_file'])
log_console = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file.setFormatter(formatter)
log_console.setFormatter(formatter)

logger.addHandler(log_file)
logger.addHandler(log_console)

mac_utils = MacOSUtils()


class VPN(object):

    # VPN Settings
    VPN_NAME = config['VPN']['vpn_name']

    # MACOS Settings
    MACOS_NOTIFICATION_ENABLED = config['MACOS'].getboolean('notifications_enabled')

    # NETWORKING Settings
    ADDRESS_TO_TUNNEL = str(config['NETWORKING']['address_to_tunnel']).split(',')
    NETWORKS_TO_TUNNEL = str(config['NETWORKING']['networks_to_tunnel']).split(',')
    VPN_DOMAINS = str(config['NETWORKING']['vpn_domains']).split(',')
    EXCLUDED_SSID = str(config['NETWORKING'].get('excluded_ssid'))

    # GENERAL Settings
    RETRY_COUNT = int(config['GENERAL']['retry_count'])
    CONNECTION_BAR_WIDTH = int(config['GENERAL']['connection_bar_width'])

    # TIMEOUTS Settings
    CONNECT_TIMEOUT = int(config['TIMEOUTS'].get('connect_timeout', 15))
    WIFI_TIMEOUT = int(config['TIMEOUTS'].get('wifi_timeout', 60))
    MAX_FAILURES = int(config['TIMEOUTS'].get('max_failures', 5))
    VPN_SLEEP_TIMER = int(config['TIMEOUTS'].get('vpn_sleep_timer', 3))

    # MOUNTS Settings
    MOUNT_USERNAME = config['MOUNTS'].get('mount_username')
    MOUNT_PASSWORD = config['MOUNTS'].get('mount_password')
    MOUNT_FOLDERS = config['MOUNTS'].getboolean('mount_folders')
    HOME_FOLDER = config['MOUNTS'].get('home_folder')
    TEAM_FOLDER = config['MOUNTS'].get('team_folder')
    TIME_MACHINE_SPARSE_BUNDLE = config['MOUNTS'].get('time_machine_sparse_bundle')
    TIME_MACHINE_SPARSE_BUNDLE_PASSWORD = config['MOUNTS'].get('time_machine_sparse_bundle_password')

    # Other settings
    vpn_util = f'{os.path.dirname(os.path.realpath(__file__))}/vpnutil'
    active = False
    active_interface = ''
    active_interface_gateway = ''
    tunnel_interface = ''
    vpn_dns_servers = []
    lost_connectivity = False
    failures = 0

    @staticmethod
    def check_connectivity(ping_count=1, test_ip_address=None):
        """
        Preform a health check.

        :return: percentage of connectivity
        """
        network_access = 0

        if test_ip_address is None:
            try:
                test_ip_address = vpn.vpn_dns_servers[0]
            except IndexError:
                # No DNS servers are set so there is no connectivity, return 0
                return network_access

        ping_command = f"ping -c {ping_count} -i 1 -W 1 {test_ip_address} | grep -oE \'\d+\.\d%\'"

        try:
            network_access = 100 - int(mac_utils.run_command(ping_command)[:-3])
            if network_access < 100:
                logger.debug(f"Send ping to {test_ip_address} with result {network_access}%")
        except:
            network_access = 0

        return network_access

    def check_internet_access(self):
        """
        Check for internet access
        :return:
        """
        logger.debug('Checking for internet access...')

        # Wait for internet connectivity to be available
        internet_access = 0
        timeout = time() + self.CONNECT_TIMEOUT
        while internet_access < 100 and time() < timeout:
            internet_access = self.check_connectivity(ping_count=2, test_ip_address='8.8.8.8')
            if internet_access == 0:
                logger.debug('Waiting for internet connectivity...')
                # Check if the routes are okay
                mac_utils.set_default_route(self.active_interface, ip_address=self.active_interface_gateway)
        if internet_access == 0:
            logger.error('Timeout while waiting for internet connectivity...')
            return False
        return True

    def get_progress_bar(self):
        """
        Create the progress bar for in the logging.

        :return: Progress bar
        :rtype: str
        """
        progress_bar_width=self.CONNECTION_BAR_WIDTH # - len('Failed Success /') <- disabled this, width can be smaller
        # then the len of the string. Looks better to use the width for the # characters only
        percentage_down = round(self.failures / vpn.MAX_FAILURES * 100) if self.failures != 0 else 0
        percentage_up = round(100 - percentage_down)
        connection = ' {percentage_up}% '.format(percentage_up=percentage_up)

        up = round(percentage_up * (progress_bar_width/100)) * '#'
        down = round(percentage_down * (progress_bar_width/100)) * ' '

        progress = '{up}{down}'.format(up=up, down=down)
        if len(connection) == 6:
            progress = progress[:round(len(progress)/2)- 3] + connection + progress[round(len(progress)/2)+3:]
        else:
            progress = progress[:round(len(progress)/2)-3] + connection + progress[round(len(progress)/2)+2:]

        bar = 'Failed [{progress}] Success '.format(progress=progress)
        return bar

    def start_tunnel(self):
        """
        Start the actual tunnel.

        :return:
        """

        logger.info(f"Ready to start VPN: {self.VPN_NAME}")

        if self.EXCLUDED_SSID.lower() in mac_utils.connected_ssid().lower():
            logger.error('You are connected with an excluded ssid. Switch ssid manually...')
            sys.exit(1)

        # Check if there is internet access before starting the tunnel
        if not self.check_internet_access():
            self.active = False
            return

        start_time = datetime.now()
        logger.debug(f'Start time: {start_time}')

        vpn_command = f'{self.vpn_util} start "{self.VPN_NAME}"'
        logger.debug(f'VPN command: "{vpn_command}"')

        result = mac_utils.run_command(vpn_command, as_user=True)
        if 'has been started' not in result and 'Connected' not in result:
            logger.info("Unable to start VPN, check your network connection.")
            logger.info(f'vpnutil responded: {result}')
            self.active = False
            return

        logger.info("Starting VPN Tunnel")

        timeout = time() + self.CONNECT_TIMEOUT
        while True:
            self.tunnel_interface = mac_utils.run_command(f'{mac_utils.IFCONFIG} | grep ipsec').split(':')[0]
            interface_details = mac_utils.run_command(f'{mac_utils.IFCONFIG} {self.tunnel_interface}')
            logger.debug('Checking if vpn interface is up...')
            if self.tunnel_interface and 'inet' in interface_details:
                break
            if time() > timeout:
                logger.info('VPN Interface not coming active ...')
                # Maybe the vpn is already running so try to set some routes
                sleep(5)
                self.active = False
                return
            sleep(2)

        logger.info('Successfully connected to VPN...')
        if self.MACOS_NOTIFICATION_ENABLED:
            pync.notify('Successfully connected to VPN...', title='VPN')

        logger.debug(f'Found tunnel interface {self.tunnel_interface}')

        # Set the default route towards the wireless or ethernet interface
        logger.debug(f'Setting default route towards: {self.active_interface}')
        mac_utils.set_default_route(self.active_interface, ip_address=self.active_interface_gateway)

        # Add the routes needed towards the tunnel
        for network in self.NETWORKS_TO_TUNNEL:
            mac_utils.add_route(network, interface=self.tunnel_interface)
        for address in self.ADDRESS_TO_TUNNEL:
            mac_utils.add_route(address, interface=self.tunnel_interface)

        self.vpn_dns_servers = mac_utils.current_nameservers

        # Add the routes for reaching the DNS servers
        logger.info('Add routes for DNS servers')
        for dns in self.vpn_dns_servers:
            mac_utils.add_route(dns, interface=self.tunnel_interface)

        # Present the routing table to the user
        logger.debug(mac_utils.parsed_routing_table())

        self.active = True
        if self.MOUNT_FOLDERS:
            self.mount_folders()

    def stop_tunnel(self):
        """
        Stop the VPN tunnel.

        :return:
        """
        logger.info("Stopping VPN...")
        if self.MOUNT_FOLDERS and not self.lost_connectivity:
            self.unmount_folders()

        vpn_command = f'{self.vpn_util} stop "{self.VPN_NAME}"'
        logger.debug(f'VPN command: "{vpn_command}"')

        result = mac_utils.run_command(vpn_command, as_user=True)
        # If 'Has been stopped' or 'Disconnected' is in the result, the VPN stopped already
        if 'has been stopped' not in result and 'Disconnected' not in result:
            logger.info("Unable to stop VPN. Please do this manually")
            logger.info(f'vpnutil responded: {result}')
        self.active = False
        mac_utils.flush_routing_table(reset_interfaces=False)
        network_interface = mac_utils.get_active_network_interface()
        gateway_address = mac_utils.gateway_for_interface(network_interface)
        mac_utils.set_default_route(self.active_interface, ip_address=gateway_address)
        if self.MACOS_NOTIFICATION_ENABLED:
            pync.notify(f'Tunnel is stopped.')

    def quit(self, *args):
        """
        Quit VPN tunnel.
        """
        self.stop_tunnel()
        sys.exit(0)

    def mount_folders(self):
        if self.active:
            logger.info("Mounting Folders...")

            if self.HOME_FOLDER:
                # Mount home folder
                mount_command = "sudo -u {os_user} osascript -e 'try' -e 'mount volume " \
                                "\"smb://{username}:{password}@{home_folder}\"' " \
                                "-e 'end try'".format(os_user=mac_utils.user, username=self.MOUNT_USERNAME,
                                                      password=self.MOUNT_PASSWORD, home_folder=self.HOME_FOLDER)

                mount_output = mac_utils.run_command(mount_command)
                logger.info(f'Mounted Home Folder: {mount_output}')

            if self.TEAM_FOLDER:
                # Mount team folder
                mount_command = "sudo -u {os_user} osascript -e 'try' -e 'mount volume " \
                                "\"smb://{username}:{password}@{team_folder}\"' " \
                                "-e 'end try'".format(os_user=mac_utils.user, username=self.MOUNT_USERNAME,
                                                      password=self.MOUNT_PASSWORD, team_folder=self.TEAM_FOLDER)
                mount_output = mac_utils.run_command(mount_command)
                logger.info(f'Mounted Team Folder: {mount_output}')

            if self.TIME_MACHINE_SPARSE_BUNDLE:
                # Mount TimeMachine sparse bundle
                home_folder_mount = "/Volumes/" + str(self.HOME_FOLDER).split('/')[-1]
                mount_command = "printf '{password}'| sudo -u {os_user} hdiutil attach -stdinpass -mountpoint " \
                                "/Volumes/TimeMachine {home_folder_mount}/{time_machine_sparse_bundle}" \
                                "".format(os_user=mac_utils.user, password=self.TIME_MACHINE_SPARSE_BUNDLE_PASSWORD,
                                          home_folder_mount=home_folder_mount,
                                          time_machine_sparse_bundle=self.TIME_MACHINE_SPARSE_BUNDLE)
                mount_output = mac_utils.run_command(mount_command)
                logger.info(f'Mounted TimeMachine: {mount_output}')

            logger.info("Folders Mounted...")

    def unmount_folders(self):
        if self.active:
            logger.info("Unmounting Folders...")

            if self.TIME_MACHINE_SPARSE_BUNDLE:
                # Mount TimeMachine sparse bundle
                home_folder_mount = "/Volumes/" + str(self.HOME_FOLDER).split('/')[1]
                mount_command = "umount -f /Volumes/TimeMachine"
                mac_utils.run_command(mount_command)

            if self.HOME_FOLDER:
                # Unmount home folder
                home_folder_mount = "/Volumes/" + str(self.HOME_FOLDER).split('/')[-1]
                mount_command = ("umount -f {home_folder}".format(home_folder=home_folder_mount))

                mac_utils.run_command(mount_command)

            if self.TEAM_FOLDER:
                # Unmount team folder
                team_folder_mount = "/Volumes/" + str(self.TEAM_FOLDER).split('/')[-1]
                mount_command = ("umount -f {team_folder}".format(team_folder=team_folder_mount))
                mac_utils.run_command(mount_command)

            logger.info("Folders Unmounted...")


if __name__ == "__main__":

    # Check if the script has been started with root
    if not os.getuid() == 0:
        logger.info("Please run this script as root.")
        sys.exit(1)

    # Characters to display the connection percentage
    spinner = itertools.cycle(['-', '/', '|', '\\'])

    # Create VPN instance
    vpn = VPN()

    # Check if a network interface is active
    vpn.active_interface = mac_utils.get_active_network_interface()
    vpn.active_interface_gateway = mac_utils.gateway_for_interface(vpn.active_interface)
    if not vpn.active_interface:
        logger.info('There is no active network interface, please make sure there is connectivity...')
        sys.exit(1)
    logger.debug(f'Active interface: {vpn.active_interface}, Gateway: {vpn.active_interface_gateway}')

    # Show the routing table if logging is debug
    logger.debug(mac_utils.parsed_routing_table())

    # On receiving ctrl + c, quit the tunnel
    signal.signal(signal.SIGINT, vpn.quit)

    try:
        vpn.failures = 0
        while True:
            # If the VPN is inactive start the tunnel
            if not vpn.active:
                # Start the tunnel
                vpn.start_tunnel()

            # Wait a while before checking the connectivity to prevent to much load
            sleep(vpn.VPN_SLEEP_TIMER) if vpn.VPN_SLEEP_TIMER else sleep(10)

            internet_connectivity = vpn.check_connectivity(ping_count=2, test_ip_address='8.8.8.8')
            connectivity = vpn.check_connectivity(ping_count=2)

            # If we have no internet connectivity but active vpn, the default gateway is probably not set correctly
            if internet_connectivity == 0 and connectivity > 50:
                active_interface = mac_utils.get_active_network_interface()
                if vpn.active_interface != active_interface:
                    logger.info('Network interface has been changed.')
                    vpn.active_interface = active_interface
                    vpn.active_interface_gateway = mac_utils.gateway_for_interface(active_interface)
                mac_utils.set_default_route(vpn.active_interface, ip_address=vpn.active_interface_gateway)
            # If we lost multiple pings, but we did not hit the maximum number of failures
            elif connectivity < 50 and vpn.failures < vpn.MAX_FAILURES:
                vpn.failures += 1
                logger.warning(f'Connectivity issues: connectivity: {connectivity}, fails: {vpn.failures}.\r')
                vpn.lost_connectivity = True
                if vpn.failures == 1 and vpn.MACOS_NOTIFICATION_ENABLED:
                    pync.notify(f'Lost Connectivity....')
                sys.stdout.write(vpn.get_progress_bar() + next(spinner) + '\r')
                sys.stdout.flush()
            # If we have enough ping response we have connectivity
            elif vpn.active and connectivity >= 50:
                if vpn.failures > 0:
                    vpn.failures -= 1
                extra_info = ''
                vpn.lost_connectivity = False
                sys.stdout.write(f'{vpn.get_progress_bar()}{next(spinner)} {extra_info}\r')
                sys.stdout.flush()
            elif vpn.failures >= vpn.MAX_FAILURES:
                if vpn.active:
                    if vpn.MACOS_NOTIFICATION_ENABLED:
                        pync.notify(f'Tunnel down, restarting...')
                    vpn.lost_connectivity = True
                    vpn.stop_tunnel()
                for attempt in range(1, vpn.RETRY_COUNT + 1):
                    if attempt == vpn.RETRY_COUNT or internet_connectivity == 0:
                        logger.info("Flushing routing table.")
                        mac_utils.flush_routing_table(reset_interfaces=True)
                        sleep(15)

                    sleep(vpn.CONNECT_TIMEOUT)
                    logger.info("Retrying to restart tunnel... attempt {nr} of {max}".format(nr=attempt,
                                                                                             max=vpn.RETRY_COUNT))
                    vpn.start_tunnel()
                    if vpn.active:
                        # Reset the failures after restoring the connection.
                        vpn.failures = 0
                        break

                if not vpn.active:
                    logger.info("Maximum number of retries reached... Exiting...")
                    sys.exit(1)

    except KeyboardInterrupt:
        pass
