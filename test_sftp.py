import unittest
from contextlib import contextmanager

import mock
import paramiko
from paramiko import sftp

from sftp import NoSSHConfigFound, NoPrivateKeyFound
import sftp


class TestSFTP(unittest.TestCase):
    def setUp(self):
        self.sut = sftp.SFTP
        self.host = 'blah.sftp.com'
        self.ssh_home = '/home/.ssh'

        # SFTP params
        self.remote_path = '/remote/data/nothing'
        self.local_path = '/local/data/nothing'
        self.get_params = (self.remote_path, self.local_path)

        # Open mock
        self.mock_open = mock.Mock(return_value=mock.MagicMock(spec=file))
        self.file_handle = self.mock_open().__enter__()

        # os mock
        self.mock_os = mock.Mock()
        self.mock_os.path.exists.return_value = True

        # paramiko mock
        self.mock_paramiko = mock.Mock()
        self.mock_paramiko.SFTPClient.from_transport.return_value = mock.MagicMock()
        self.sftp_handle = self.mock_paramiko.SFTPClient.from_transport.return_value
        self.sftp_handle.get = mock.Mock()
        self.sftp_handle.listdir = mock.Mock()
        self.sftp_handle.put = mock.Mock()
        self.sftp_handle.remove = mock.Mock()
        self.sftp_handle.rename = mock.Mock()
        self.mock_get_transport = mock.Mock(return_value='mock_transport')

        self.remote_files = ['some_file.tgz', 'another_file.zip', 'further_file.tgz']
        self.mock_os.path.join.side_effect = ['{ssh_home}/config'.format(ssh_home=self.ssh_home),
                                              '/remote/data/nothing/some_file.tgz',
                                              '/local/data/some_file.tgz',
                                              '/remote/data/nothing/further_file.tgz',
                                              '/local/data/further_file.tgz']

    @contextmanager
    def limited_runner(self):
        with mock.patch('sftp.open', self.mock_open),\
             mock.patch('sftp.paramiko', self.mock_paramiko):
            yield

    @contextmanager
    def default_runner(self):
        with mock.patch('sftp.pwd'),\
             mock.patch('sftp.open', self.mock_open),\
             mock.patch('sftp.paramiko', self.mock_paramiko), \
             mock.patch('sftp.os', self.mock_os), \
             mock.patch('sftp.SFTP._get_config'), \
             mock.patch('sftp.SFTP._get_private_key'),\
             mock.patch('sftp.SFTP._get_transport', self.mock_get_transport):
            yield

    def test_get_config_raises_when_ssh_config_not_found(self):
        # Setup
        self.mock_os.path.exists.return_value = False

        with self.limited_runner():
            with mock.patch('sftp.os', self.mock_os),\
                 mock.patch('sftp.SFTP._get_private_key'),\
                 mock.patch('sftp.SFTP._get_transport'):

                # Test & Assert
                sut = self.sut(self.host)
                self.assertRaises(NoSSHConfigFound, sut._get_config)


    def test_get_private_key_expands_userdir(self):
        # Setup
        key_path = ' ~/.ssh/sftp-dsa' # Note the leading space - paramiko parsing bug may leave this.
        with mock.patch('sftp.paramiko', self.mock_paramiko),\
            mock.patch('sftp.SFTP._get_transport', self.mock_get_transport),\
            mock.patch('sftp.os', self.mock_os):

            self.mock_os.path.expanduser = lambda item: item.replace('~', '/home/me')

            sut = self.sut(self.host)
            # Test
            sut._get_private_key(key_path)
            # Assert
            self.mock_paramiko.RSAKey.from_private_key_file.assert_called_once_with(
                '/home/me/.ssh/sftp-dsa')


    def test_dss_key_returned_when_dsa_key_found(self):
        # Setup
        self.mock_paramiko.RSAKey.from_private_key_file.side_effect = paramiko.ssh_exception.SSHException

        with \
                mock.patch('sftp.SFTP._get_transport', self.mock_get_transport),\
                mock.patch('sftp.paramiko', self.mock_paramiko), \
                mock.patch('sftp.os', self.mock_os), \
                mock.patch('sftp.SFTP._get_transport'):

            self.mock_os.path.expanduser.return_value = 'key'
            sut = self.sut(self.host)
            # Test
            sut._get_private_key('key')
            # Assert
            self.mock_paramiko.DSSKey.from_private_key_file.assert_has_calls([
                mock.call('key')
            ])

    def test_ssh_config_ignored_when_user_and_pkey_defined(self):
        # Setup
        user = 'blah'
        pkey = 'new_key'
        connect_args = {'username': user, 'pkey': pkey}
        mock_get_config = mock.Mock()
        mock_get_private_key = mock.Mock(return_value=pkey)

        with \
                mock.patch('sftp.pwd'), \
                mock.patch('sftp.open', self.mock_open), \
                mock.patch('sftp.paramiko', self.mock_paramiko), \
                mock.patch('sftp.os', self.mock_os), \
                mock.patch('sftp.SFTP._get_config', mock_get_config), \
                mock.patch('sftp.SFTP._get_private_key', mock_get_private_key):
            # Test
            sut = self.sut(self.host, user=user, pkey=pkey)
            sut.create_client()

            # Assert
            mock_get_private_key.assert_has_calls([mock.call(pkey)])
            self.mock_paramiko.Transport.return_value.connect.assert_has_calls([mock.call(**connect_args)])
            self.assertEqual(sut.ssh_config, None)

    def test_ssh_config_used_when_user_and_pkey_undefined(self):
        # Setup
        pkey = 'home_key'
        #   Note the deliberate leading spaces here - paramiko bug will produce them.
        ssh_config = {'identityfile': pkey, 'hostname': ' some_host', 'port': 456, 'user': ' some_user'}
        connect_args = {'username': 'some_user', 'pkey': 'home_key'}
        mock_get_config = mock.Mock(return_value=ssh_config)
        mock_get_private_key = mock.Mock(return_value=pkey)

        with \
                mock.patch('sftp.pwd.getpwuid', mock.Mock(return_value=['sys_user'])), \
                mock.patch('sftp.open', self.mock_open), \
                mock.patch('sftp.paramiko', self.mock_paramiko), \
                mock.patch('sftp.os', self.mock_os), \
                mock.patch('sftp.SFTP._get_config', mock_get_config), \
                mock.patch('sftp.SFTP._get_private_key', mock_get_private_key):
            # Test
            sut = self.sut(self.host)
            sut.create_client()

            # Assert
            self.mock_paramiko.Transport.return_value.connect.assert_has_calls([mock.call(**connect_args)])
            self.assertEqual(sut.user, None)
            self.assertEqual(sut.pkey, None)
            self.assertEqual(sut.ssh_config, ssh_config)

    def test_ssh_home_searched_for_private_key_when_ssh_config_missing_key(self):
        # Setup
        home_key = 'id_rsa'
        ssh_config = {'hostname': 'some_host', 'port': 456, 'user': 'some_user'}
        connect_args = {'username': ssh_config['user'], 'pkey': home_key}
        mock_get_config = mock.Mock(return_value=ssh_config)
        self.mock_os.expand_user.return_value = self.ssh_home
        self.mock_os.listdir.return_value = ['config', home_key]
        self.mock_paramiko.RSAKey.from_private_key_file.side_effect = [paramiko.ssh_exception.SSHException,
                                                                       'id_rsa']
        self.mock_paramiko.DSSKey.from_private_key_file.side_effect = [paramiko.ssh_exception.SSHException]

        with \
                mock.patch('sftp.pwd.getpwuid'), \
                mock.patch('sftp.open'), \
                mock.patch('sftp.paramiko', self.mock_paramiko), \
                mock.patch('sftp.os', self.mock_os), \
                mock.patch('sftp.SFTP._get_config', mock_get_config):
            # Test
            sut = self.sut(self.host)
            sut.create_client()

            # Assert
            self.mock_paramiko.Transport.return_value.connect.assert_has_calls([mock.call(**connect_args)])

    def test_no_private_key_raised_when_no_compatible_key_found(self):
        # Setup
        ssh_config = {'hostname': 'some_host', 'port': 456, 'user': 'some_user'}
        mock_get_config = mock.Mock(return_value=ssh_config)
        self.mock_os.expand_user.return_value = self.ssh_home
        self.mock_os.listdir.return_value = ['config']
        self.mock_paramiko.RSAKey.from_private_key_file.side_effect = [paramiko.ssh_exception.SSHException,
                                                                       paramiko.ssh_exception.SSHException]
        self.mock_paramiko.DSSKey.from_private_key_file.side_effect = [paramiko.ssh_exception.SSHException,
                                                                       paramiko.ssh_exception.SSHException]

        with \
                mock.patch('sftp.pwd.getpwuid'), \
                mock.patch('sftp.open'), \
                mock.patch('sftp.paramiko', self.mock_paramiko), \
                mock.patch('sftp.os', self.mock_os), \
                mock.patch('sftp.SFTP._get_config', mock_get_config):

            # Test & Assert
            with self.assertRaises(NoPrivateKeyFound):
                sut = self.sut(self.host)
                sut.create_client()

    def test_list_files_returns_correct_list_of_files(self):
        # Setup
        self.sftp_handle.listdir.return_value = ['a', 'b', 'c']
        list_params = ('/data/nothing',)
        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            returned_files = sut.list_files(*list_params)
            # Assert
            self.sftp_handle.listdir.assert_has_calls([mock.call(*list_params)])
            self.assertEqual(returned_files, ['a', 'b', 'c'])

    def test_get_file_calls_sftp_client_with_correct_calls(self):
        # Setup
        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.get_file(*self.get_params)
            # Assert
            self.sftp_handle.get.assert_has_calls([mock.call(*self.get_params)])

    def test_remove_file_calls_sftp_client_with_correct_calls(self):
        # Setup
        remove_params = ('/remote/data/nothing',)
        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.remove_file(*remove_params)
            # Assert
            self.sftp_handle.remove.assert_has_calls([mock.call(*remove_params)])

    def test_rename_file_calls_sftp_client_with_correct_calls(self):
        # Setup
        rename_params = ('/remote/data/nothing', '/remote/data/something')
        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.rename_file(*rename_params)
            # Assert
            self.sftp_handle.rename.assert_has_calls([mock.call(*rename_params)])

    def test_upload_file_calls_sftp_client_with_correct_calls(self):
        # Setup
        upload_params = ('/local/data/nothing', '/remote/data/nothing')
        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.upload_file(*upload_params)
            # Assert
            self.sftp_handle.put.assert_has_calls([mock.call(*upload_params)])

    def test_upload_files_calls_sftp_client_with_correct_calls(self):
        # Setup
        upload_params = (['/local/data/nothing', '/local/foo/bar'], '/remote/data')
        self.mock_os.path.basename.side_effect = ['nothing', 'bar']
        self.mock_os.path.join.side_effect = ['{ssh_home}/config'.format(ssh_home=self.ssh_home),
                                              '/remote/data/nothing',
                                              '/remote/data/bar']

        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.upload_files(*upload_params)

            # Assert
            self.sftp_handle.put.assert_has_calls([mock.call(upload_params[0][0], '/remote/data/nothing'),
                                                   mock.call(upload_params[0][1], '/remote/data/bar')])

    def test_get_files_starts_with_filter_returns_correct_list_of_files(self):
        # Setup
        starts_with = 'some_file'
        self.sftp_handle.listdir.return_value = self.remote_files

        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.get_files(*self.get_params, starts_with=starts_with)
            # Assert
            self.sftp_handle.listdir.assert_called_with(self.get_params[0])
            self.sftp_handle.get.assert_has_calls([mock.call('/remote/data/nothing/some_file.tgz',
                                                             '/local/data/some_file.tgz')])

    def test_get_files_ends_with_filter_returns_correct_list_of_files(self):
        # Setup
        ends_with = 'tgz'
        self.sftp_handle.listdir.return_value = self.remote_files

        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.get_files(*self.get_params, ends_with=ends_with)
            # Assert
            self.sftp_handle.listdir.assert_called_with(self.get_params[0])
            self.sftp_handle.get.assert_has_calls([mock.call('/remote/data/nothing/some_file.tgz',
                                                             '/local/data/some_file.tgz'),
                                                   mock.call('/remote/data/nothing/further_file.tgz',
                                                             '/local/data/further_file.tgz')])

    def test_get_files_with_delete_files_calls_sftp_client_remove(self):
        # Setup
        ends_with = 'tgz'
        self.sftp_handle.listdir.return_value = self.remote_files

        with self.default_runner():
            sut = self.sut(self.host)
            # Test
            sut.get_files(self.remote_path, ends_with=ends_with, delete_files=True)
            # Assert
            self.sftp_handle.listdir.assert_called_with(self.get_params[0])
            self.sftp_handle.get.assert_has_calls([mock.call('/remote/data/nothing/some_file.tgz',
                                                             '/local/data/some_file.tgz'),
                                                   mock.call('/remote/data/nothing/further_file.tgz',
                                                             '/local/data/further_file.tgz')])
            self.sftp_handle.remove.assert_has_calls([mock.call('/remote/data/nothing/some_file.tgz'),
                                                      mock.call('/remote/data/nothing/further_file.tgz')])
