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
    USER_ID = config['MACOS']['user_id']
    USERNAME = config['MACOS']['username']
    MACOS_NOTIFICATION_ENABLED = config['NOTIFICATION'].getboolean('notifications_enabled')

    # NETWORKING Settings
    ADDRESS_TO_TUNNEL = str(config['NETWORKING']['address_to_tunnel']).split(',')
    NETWORKS_TO_TUNNEL = str(config['NETWORKING']['networks_to_tunnel']).split(',')
    VPN_DOMAINS = str(config['NETWORKING']['vpn_domains']).split(',')
    TUNNEL_INTERFACE = config['NETWORKING']['tunnel_interface']
    WIRELESS_INTERFACE = config['NETWORKING']['wireless_interface']

    # GENERAL Settings
    RETRY_COUNT = int(config['GENERAL']['retry_count'])
    CONNECTION_BAR_WIDTH = int(config['GENERAL']['connection_bar_width'])

    # TIMEOUTS Settings
    RECONNECT_TIMEOUT = int(config['TIMEOUTS']['reconnect_timeout'])
    CONNECT_TIMEOUT = int(config['TIMEOUTS']['connect_timeout'])
    TOKEN_TIMEOUT = int(config['TIMEOUTS']['token_timeout'])
    WIFI_TIMEOUT = int(config['TIMEOUTS']['wifi_timeout'])
    MAX_FAILURES = int(config['TIMEOUTS']['max_failures'])
    VPN_SLEEP_TIMER = int(config['TIMEOUTS']['vpn_sleep_timer'])

    # MOUNTS Settings
    MOUNT_USERNAME = config['MOUNTS'].get('mount_username')
    MOUNT_PASSWORD = config['MOUNTS'].get('mount_password')
    MOUNT_FOLDERS = config['MOUNTS'].getboolean('mount_folders')
    HOME_FOLDER = config['MOUNTS'].get('home_folder')
    TEAM_FOLDER = config['MOUNTS'].get('team_folder')
    TIME_MACHINE_SPARSE_BUNDLE = config['MOUNTS'].get('time_machine_sparse_bundle')
    TIME_MACHINE_SPARSE_BUNDLE_PASSWORD = config['MOUNTS'].get('time_machine_sparse_bundle_password')

    # Other settings
    VPN_UTIL = f'{os.path.dirname(os.path.realpath(__file__))}/vpnutil'
    tunnel = None
    active = False
    vpn_dns_servers = []

    @staticmethod
    def check_connectivity(ping_count=1, test_ip_address=None, lost_connectivity=False):
        """
        Preform a health check.

        :return: percentage of connectivity
        """
        connectivity = 0

        if test_ip_address is None:
            try:
                test_ip_address = vpn.vpn_dns_servers[0]
            except IndexError:
                # No DNS servers are set so there is no connectivity, return 0
                return connectivity

        ping_command = f"ping -c {ping_count} -i 1 -W 1 {test_ip_address} | grep -oE \'\d+\.\d%\'"

        # Try to run the following ping command
        if lost_connectivity:
            logger.debug(ping_command)

        try:
            connectivity = 100 - int(mac_utils.run_command(ping_command)[:-3])
            if connectivity < 100:
                logger.debug(f"Send ping to {test_ip_address} with result {connectivity}%")
        except:
            connectivity = 0

        return connectivity

    def check_internet_access(self):
        """
        Check for internet access
        :return:
        """
        logger.debug('Checking for internet access...')

        # Wait for internet connectivity to be available
        internet_connectivity = 0
        timeout = time() + self.CONNECT_TIMEOUT
        while internet_connectivity < 100 and time() < timeout:
            internet_connectivity = self.check_connectivity(ping_count=2, test_ip_address='8.8.8.8')
            if internet_connectivity < 0:
                logger.debug('Waiting for internet connectivity...')
            sleep(1)

        if internet_connectivity == 0:
            logger.debug('Timeout while waiting for internet connectivity...')
            mac_utils.flush_routing_table()
            return False
        else:
            return True

    def get_progress_bar(self, failures):
        """
        Create the progress bar for in the logging.

        :param failures: number of failed pings
        :type failures: float
        :return: Progress bar
        :rtype: str
        """
        progress_bar_width=self.CONNECTION_BAR_WIDTH # - len('Failed Success /') <- disabled this, width can be smaller
        # then the len of the string. Looks better to use the width for the # characters only
        percentage_down = round(failures / vpn.MAX_FAILURES * 100) if failures != 0 else 0
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

    def start_tunnel(self, lost_connectivity=False):
        """
        Start the actual tunnel.

        :return:
        """

        logger.info("Starting VPN...")

        # self.switch_wifi()
        # Check if there is internet access before starting the tunnel
        if not self.check_internet_access():
            return False

        start_time = datetime.now()
        logger.debug(f'Start time: {start_time}')

        vpn_command = f'{self.VPN_UTIL} start "{self.VPN_NAME}"'
        logger.debug(f'VPN command: "{vpn_command}"')

        result = mac_utils.run_command(vpn_command, self.USER_ID)
        if 'has been started' not in result:
            logger.info("Unable to start VPN, check your network connection.")
            logger.info(f'vpnutil responded: {result}')
            return False

        logger.info("Starting VPN Tunnel")

        timeout = time() + self.CONNECT_TIMEOUT
        while vpn.check_connectivity(ping_count=3, lost_connectivity=lost_connectivity, test_ip_address='10.68.29.189') == 0:
            logger.info('Checking connectivity...')
            if time() > timeout:
                logger.info('Timeout during connecting to VPN...')
                mac_utils.flush_routing_table()
                return False

        logger.info('Successfully connected to VPN...')
        if self.MACOS_NOTIFICATION_ENABLED:
            pync.notify('Successfully connected to VPN...', title='VPN')

        # Set the default route towards the wireless or ethernet interface
        mac_utils.set_default_route('en0')
        # Add the routes needed towards the tunnel
        for network in self.NETWORKS_TO_TUNNEL:
            mac_utils.add_route(network, interface=self.TUNNEL_INTERFACE)
        for address in self.ADDRESS_TO_TUNNEL:
            mac_utils.add_route(address, interface=self.TUNNEL_INTERFACE)

        # Add the routes for reaching the DNS servers
        # for dns in self.vpn_dns_servers:
        #     mac_utils.add_route(dns, interface=self.TUNNEL_INTERFACE)
        #
        # router = mac_utils.current_router(self.WIRELESS_INTERFACE)
        # # Add the default route
        # mac_utils.add_route('default', gateway=router)

        # Present the routing table to the user
        logger.debug(mac_utils.parsed_routing_table())

        self.active = True
        if self.MOUNT_FOLDERS:
            self.mount_folders()
        return True

    def stop_tunnel(self, lost_connectivity=False):
        """
        Stop the VPN tunnel.

        :param lost_connectivity: Variable to determine if the connection was lost
        :type: bool
        :return:
        """
        logger.info("Stopping VPN...")
        if self.MOUNT_FOLDERS and not lost_connectivity:
            self.unmount_folders()

        if self.active:
            vpn_command = f'{self.VPN_UTIL} stop "{self.VPN_NAME}"'
            logger.debug(f'VPN command: "{vpn_command}"')

            result = mac_utils.run_command(vpn_command, self.USER_ID)
            if 'has been stopped' not in result:
                logger.info("Unable to stop VPN. Please do this manually")
                logger.info(f'vpnutil responded: {result}')
            self.active = False
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
                                "-e 'end try'".format(os_user=self.USERNAME, username=self.MOUNT_USERNAME,
                                                      password=self.MOUNT_PASSWORD, home_folder=self.HOME_FOLDER)

                mount_output = mac_utils.run_command(mount_command)
                logger.info(f'Mounted Home Folder: {mount_output}')

            if self.TEAM_FOLDER:
                # Mount team folder
                mount_command = "sudo -u {os_user} osascript -e 'try' -e 'mount volume " \
                                "\"smb://{username}:{password}@{team_folder}\"' " \
                                "-e 'end try'".format(os_user=self.USERNAME, username=self.MOUNT_USERNAME,
                                                      password=self.MOUNT_PASSWORD, team_folder=self.TEAM_FOLDER)
                mount_output = mac_utils.run_command(mount_command)
                logger.info(f'Mounted Team Folder: {mount_output}')

            if self.TIME_MACHINE_SPARSE_BUNDLE:
                # Mount TimeMachine sparse bundle
                home_folder_mount = "/Volumes/" + str(self.HOME_FOLDER).split('/')[-1]
                mount_command = "printf '{password}'| sudo -u {os_user} hdiutil attach -stdinpass -mountpoint " \
                                "/Volumes/TimeMachine {home_folder_mount}/{time_machine_sparse_bundle}" \
                                "".format(os_user=self.USERNAME, password=self.TIME_MACHINE_SPARSE_BUNDLE_PASSWORD,
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

    # Show the routing table if logging is debug
    logger.debug(mac_utils.parsed_routing_table())

    # Create VPN instance and start the tunnel
    vpn = VPN()
    vpn.start_tunnel()

    # On receiving ctrl + c, quit the tunnel
    signal.signal(signal.SIGINT, vpn.quit)

    # Get the nameservers for the vpn. Those are used to check if the vpn is active
    vpn.vpn_dns_servers = mac_utils.current_nameservers

    try:
        failures = 0
        lost_connectivity = False
        while True:
            sleep(vpn.VPN_SLEEP_TIMER) if vpn.VPN_SLEEP_TIMER else sleep(30)
            connectivity = vpn.check_connectivity(ping_count=2, lost_connectivity=lost_connectivity)
            if connectivity < 50 and failures < vpn.MAX_FAILURES:
                failures += 1
                logger.warning(f'Connectivity Degradation: connectivity: {connectivity}, total fails: {failures}.\r')
                lost_connectivity = True
                if failures == 1 and vpn.MACOS_NOTIFICATION_ENABLED:
                    pync.notify(f'Lost Connectivity....')
                sys.stdout.write(vpn.get_progress_bar(failures=failures) + next(spinner) + '\r')
                sys.stdout.flush()
            elif vpn.active and connectivity >= 50:
                if failures > 0:
                    failures -= 1
                extra_info = ''
                lost_connectivity = False
                sys.stdout.write(f'{vpn.get_progress_bar(failures=failures)}{next(spinner)} {extra_info}\r')
                sys.stdout.flush()
            elif failures >= vpn.MAX_FAILURES:
                if vpn.active:
                    if vpn.MACOS_NOTIFICATION_ENABLED:
                        pync.notify(f'Tunnel down, restarting...')
                    vpn.stop_tunnel(lost_connectivity=True)
                for attempt in range(1, vpn.RETRY_COUNT + 1):
                    if attempt == vpn.RETRY_COUNT:
                        logger.info("Last retry, flushing routing table as a last resort.")
                        mac_utils.flush_routing_table()

                    sleep(vpn.CONNECT_TIMEOUT)
                    logger.info("Retrying to restart tunnel... attempt {nr} of {max}".format(nr=attempt,
                                                                                             max=vpn.RETRY_COUNT))
                    vpn.start_tunnel()
                    if vpn.active:
                        # Reset the failures after restoring the connection.
                        failures = 0
                        break

                if not vpn.active:
                    logger.info("Maximum number of retries reached... Exiting...")
                    sys.exit(1)

    except KeyboardInterrupt:
        pass
