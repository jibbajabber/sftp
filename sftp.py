import os
import pwd
import logging
from contextlib import contextmanager
import subprocess

import paramiko
from paramiko import SSHException

logger = logging.getLogger(__name__)


class NoSSHConfigFound(Exception):
    pass


class NoPrivateKeyFound(Exception):
    pass


class SftpCommandError(subprocess.CalledProcessError):
    pass


class SFTP(object):
    def __init__(self, host, pkey=None, port=22, user=None, ssh_config_path=None):
        """
        SFTP helper:
          Connects to sftp servers.
          Default behaviour is to use ssh config for hostname, port & private key.
          If pkey & user defined, ssh config is not used.
          Can be used as a context manager e.g:
            with SFTP('host') as sftp_connection:
                sftp.list_files(path)
                sftp.upload_file(local, remote)
                ...

        :param host: host or alias <alias in the case of looking up ssh details in ssh config>
        :param port: port to connect to
        :param user: user to connect with
        :param pkey: path to private key to use
        :param ssh_config_path: path to ssh config (will use ~/.ssh/config when undefined)
        """
        self.host = host
        self.pkey = pkey
        self.port = port
        self.user = user
        self.ssh_config = None
        self.ssh_config_path = ssh_config_path or os.path.join(os.path.expanduser('~/.ssh'), 'config')
        self.logger = logger
        self.transport = None
        self.sftp = None

    def __enter__(self):
        self.create_client()
        return self

    def __exit__(self, *args):
        self.transport.close()

    def _get_config(self):
        logger.info("Loading config from {}".format(self.ssh_config_path))
        if os.path.exists(self.ssh_config_path):
            config = paramiko.SSHConfig()
            with open(self.ssh_config_path) as ssh_config:
                config.parse(ssh_config)

            return config.lookup(self.host)
        else:
            raise NoSSHConfigFound

    def _get_private_key(self, key_path):
        if key_path is not None:
            # Older versions of paramiko do not strip leading whitespace from ssh config parsed items
            key_path = os.path.expanduser(key_path.strip())
        try:
            self.logger.debug('Attempting to use RSA key.. "{}"'.format(key_path))
            return paramiko.RSAKey.from_private_key_file(key_path)
        except SSHException as e:
            self.logger.debug('  -> Attempting to use DSS Key {0} as RSA key failed:{1}'.format(key_path, e))
            return paramiko.DSSKey.from_private_key_file(key_path)

    def get_config_connection_details(self):
        self.ssh_config = self._get_config()

        private_key = None
        private_key_path = self.ssh_config.get('identityfile', None)

        # Newer versions of paramiko return a list for ssh config['identityfile'] (private key path)
        #  handle this here
        if isinstance(private_key_path, list):
            if len(private_key_path) > 1:
                self.logger.warning('Private key path has multiple items {items}, using first key "{key}"'.format(
                    items=private_key_path, key=private_key_path[0]))
            private_key_path = private_key_path[0]

        try:
            private_key = self._get_private_key(private_key_path)
        except SSHException:
            self.logger.warning('No RSA or DSA private key defined in ssh config, looking in ~/.ssh')
            ssh_home = os.path.os.path.expanduser('~/.ssh')
            if os.path.exists(ssh_home):
                self.logger.debug('  -> Checking {ssh_home} for a rsa or dss key'.format(ssh_home=ssh_home))
                items_to_check = os.listdir(ssh_home)
                for key in ('id_rsa', 'id_dsa'):
                    if key in items_to_check:
                        self.logger.debug('  -> {0} key found'.format(key))
                        private_key = self._get_private_key(os.path.join(ssh_home, key))
                        break
                if not private_key:
                    raise NoPrivateKeyFound('Either no key found in ssh config or ~/.ssh, or key is not RSA or DSS')

        # Older versions of paramiko do not strip leading whitespace from ssh config parsed items
        hostname = self.ssh_config.get('hostname', self.host).strip()
        port = self.ssh_config.get('port', self.port)
        user = self.ssh_config.get('user', self.user or pwd.getpwuid(os.getuid())[0]).strip()
        return hostname, user, port, private_key

    def _get_transport(self):
        if self.user and self.pkey:
            self.logger.debug('Using provided host, user & private key over ssh config')
            private_key = self._get_private_key(self.pkey)
            hostname = self.host
            port = self.port
            connect_args = {'username': self.user, 'pkey': private_key}
        else:
            hostname, user, port, private_key = self.get_config_connection_details()
            self.logger.debug('Using ssh config for host, user & private key')
            connect_args = {'username': user, 'pkey': private_key}

        # Let paramiko handle socket creation from tuple
        transport = paramiko.Transport((hostname, port))
        transport.connect(**connect_args)
        return transport

    def create_client(self):
        self.logger.info('Connecting to {0}'.format(self.host))
        self.transport = self._get_transport()
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)

    def _connect(self, method, args, **kwargs):
        return self.sftp.__getattribute__(method)(*args, **kwargs)

    def client(self, method, args, **kwargs):
        try:
            if self.transport is None or self.sftp is None:
                self.create_client()
            return self._connect(method, args, **kwargs)
        except SSHException, e:
            self.logger.fatal("Error making connection or during {m}:\n{e}".format(m=method, e=e))
            raise

    def list_files(self, remote_path):
        return self.client('listdir', [remote_path])

    def get_file(self, remote_file, local_path):
        return self.client('get', [remote_file, local_path])

    @contextmanager
    def open_file(self, remote_file, mode='r'):
        fd = self.client('file', [remote_file], mode='r')
        try:
            yield fd
        finally:
            fd.close()

    def remove_file(self, remote_file):
        return self.client('remove', [remote_file])

    def rename_file(self, old_remote_path, new_remote_path):
        return self.client('rename', [old_remote_path, new_remote_path])

    def upload_file(self, local_file, remote_path):
        return self.client('put', [local_file, remote_path])

    def upload_files(self, files_list, remote_path):
        try:
            for local_file in files_list:
                remote_file_name = os.path.join(remote_path, os.path.basename(local_file))
                self.upload_file(local_file, remote_file_name)

        except paramiko.SSHException as e:
            self.logger.fatal("Error either connecting or uploading to {rf}:\n{e}".format(rf=remote_path, e=e))
            raise

    def get_files(self, remote_path, local_path=None, delete_files=False, starts_with=None, ends_with=None):
        local_path = local_path or os.getcwd()
        try:
            # find & filter matching remote files
            remote_files = [remote_file for remote_file in self.list_files(remote_path)
                            if (starts_with and remote_file.startswith(starts_with))
                            or (ends_with and remote_file.endswith(ends_with))]

            self.logger.info('Remote files found:{rf}'.format(rf=remote_files))

            for file_name in remote_files:
                remote_file = os.path.join(remote_path, file_name)
                local_file = os.path.join(local_path, file_name)
                self.logger.info("Getting file:{f}".format(f=remote_file))

                # fetch file
                self.get_file(remote_file, local_file)
                if delete_files:
                    self.logger.info("deleting remote file: %s" % remote_file)
                    self.remove_file(remote_file)
        except paramiko.SSHException:
            self.logger.fatal("Error making connection")
            raise
