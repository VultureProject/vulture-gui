import os
from unittest import mock
from django.test import TestCase
from django.core.exceptions import ValidationError

from gui.utils.validators import (
    AbsolutePathValidator,
    SpoolDirectoryValidator,
    validate_spool_directory
)
from services.rsyslogd.rsyslog import ensure_spool_directory, check_spool_directory


class AbsolutePathValidatorTest(TestCase):
    """Tests for AbsolutePathValidator."""
    
    def setUp(self):
        self.validator = AbsolutePathValidator()
    
    def test_valid_absolute_path(self):
        """Valid absolute paths should pass."""
        valid_paths = [
            '/var/log/test',
            '/tmp/queue',
            '/var/spool/rsyslog/myqueue',
            '/tmp/test-queue_1.0',
        ]
        for path in valid_paths:
            with self.subTest(path=path):
                # Should not raise
                self.assertEqual(self.validator(path), path)
    
    def test_relative_path_fails(self):
        """Relative paths should fail."""
        with self.assertRaises(ValidationError) as ctx:
            self.validator('var/log/test')
        self.assertEqual(ctx.exception.code, 'not_absolute')
    
    def test_path_escape_fails(self):
        """Paths with ../ should fail."""
        invalid_paths = [
            '/var/../etc/passwd',
            '/var/log/../../etc',
            '/tmp/test/../../../root',
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValidationError) as ctx:
                    self.validator(path)
                self.assertEqual(ctx.exception.code, 'path_escape')
    
    def test_invalid_chars_fail(self):
        """Paths with invalid characters should fail."""
        invalid_paths = [
            '/var/log/test;rm -rf /',
            '/var/log/test$(whoami)',
            '/var/log/test`id`',
            '/var/log/test|cat',
            '/var/log/test name',  # space
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValidationError) as ctx:
                    self.validator(path)
                self.assertEqual(ctx.exception.code, 'invalid_chars')
    
    def test_empty_path_fails(self):
        """Empty path should fail."""
        with self.assertRaises(ValidationError):
            self.validator('')
        with self.assertRaises(ValidationError):
            self.validator(None)


class SpoolDirectoryValidatorTest(TestCase):
    """Tests for SpoolDirectoryValidator."""
    
    def setUp(self):
        self.validator = SpoolDirectoryValidator()
    
    def test_valid_spool_directories(self):
        """Valid spool directories under /tmp or /var should pass."""
        valid_paths = [
            '/var/spool/rsyslog',
            '/var/spool/rsyslog/queue1',
            '/tmp/rsyslog-queue',
            '/var/log/queues/frontend_1',
        ]
        for path in valid_paths:
            with self.subTest(path=path):
                self.assertEqual(self.validator(path), path)
    
    def test_invalid_root_directories(self):
        """Paths not under /tmp or /var should fail."""
        invalid_paths = [
            '/etc/rsyslog',
            '/home/user/queue',
            '/usr/local/spool',
            '/root/queue',
            '/opt/rsyslog',
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValidationError) as ctx:
                    self.validator(path)
                self.assertEqual(ctx.exception.code, 'invalid_root')
    
    def test_root_dirs_directly_fail(self):
        """Using /tmp or /var directly should fail."""
        with self.assertRaises(ValidationError) as ctx:
            self.validator('/tmp')
        self.assertEqual(ctx.exception.code, 'is_root')
        
        with self.assertRaises(ValidationError) as ctx:
            self.validator('/var')
        self.assertEqual(ctx.exception.code, 'is_root')
    
    def test_inherits_absolute_path_validation(self):
        """Should also validate as absolute path."""
        # Relative path
        with self.assertRaises(ValidationError) as ctx:
            self.validator('var/spool/test')
        self.assertEqual(ctx.exception.code, 'not_absolute')
        
        # Path escape
        with self.assertRaises(ValidationError) as ctx:
            self.validator('/var/../etc/test')
        self.assertEqual(ctx.exception.code, 'path_escape')


class EnsureSpoolDirectoryTest(TestCase):
    """Tests for ensure_spool_directory function with mocked os calls."""
    
    @mock.patch('toolkit.system.rsyslog.os.chmod')
    @mock.patch('toolkit.system.rsyslog.os.chown')
    @mock.patch('toolkit.system.rsyslog.os.access')
    @mock.patch('toolkit.system.rsyslog.os.makedirs')
    @mock.patch('toolkit.system.rsyslog.os.path.exists')
    @mock.patch('toolkit.system.rsyslog.grp.getgrnam')
    @mock.patch('toolkit.system.rsyslog.pwd.getpwnam')
    def test_creates_directory_when_missing(
        self, mock_getpwnam, mock_getgrnam, mock_exists,
        mock_makedirs, mock_access, mock_chown, mock_chmod
    ):
        """Should create directory when it doesn't exist."""
        # Setup mocks
        mock_exists.return_value = False
        mock_access.return_value = True
        mock_getpwnam.return_value = mock.Mock(pw_uid=1001)
        mock_getgrnam.return_value = mock.Mock(gr_gid=1001)
        
        result = ensure_spool_directory('/var/spool/rsyslog/test')
        
        self.assertTrue(result['status'])
        mock_makedirs.assert_called_once()
        mock_chown.assert_called_once()
        mock_chmod.assert_called_once()
    
    @mock.patch('toolkit.system.rsyslog.os.chmod')
    @mock.patch('toolkit.system.rsyslog.os.chown')
    @mock.patch('toolkit.system.rsyslog.os.access')
    @mock.patch('toolkit.system.rsyslog.os.path.exists')
    @mock.patch('toolkit.system.rsyslog.grp.getgrnam')
    @mock.patch('toolkit.system.rsyslog.pwd.getpwnam')
    def test_skips_creation_when_exists(
        self, mock_getpwnam, mock_getgrnam, mock_exists,
        mock_access, mock_chown, mock_chmod
    ):
        """Should not create directory when it already exists."""
        mock_exists.return_value = True
        mock_access.return_value = True
        mock_getpwnam.return_value = mock.Mock(pw_uid=1001)
        mock_getgrnam.return_value = mock.Mock(gr_gid=1001)
        
        with mock.patch('toolkit.system.rsyslog.os.makedirs') as mock_makedirs:
            result = ensure_spool_directory('/var/spool/rsyslog/test')
        
        self.assertTrue(result['status'])
        mock_makedirs.assert_not_called()
    
    def test_rejects_invalid_paths(self):
        """Should reject paths not under /tmp or /var."""
        with self.assertRaises(ValueError):
            ensure_spool_directory('/etc/rsyslog/queue')
        
        with self.assertRaises(ValueError):
            ensure_spool_directory('/var/../etc/queue')
    
    @mock.patch('toolkit.system.rsyslog.os.makedirs')
    @mock.patch('toolkit.system.rsyslog.os.path.exists')
    def test_handles_permission_error(self, mock_exists, mock_makedirs):
        """Should handle PermissionError gracefully."""
        mock_exists.return_value = False
        mock_makedirs.side_effect = PermissionError("Access denied")
        
        result = ensure_spool_directory('/var/spool/rsyslog/test')
        
        self.assertFalse(result['status'])
        self.assertIn('Permission denied', result['message'])
    
    @mock.patch('toolkit.system.rsyslog.os.chmod')
    @mock.patch('toolkit.system.rsyslog.os.chown')
    @mock.patch('toolkit.system.rsyslog.os.access')
    @mock.patch('toolkit.system.rsyslog.os.makedirs')
    @mock.patch('toolkit.system.rsyslog.os.path.exists')
    @mock.patch('toolkit.system.rsyslog.grp.getgrnam')
    @mock.patch('toolkit.system.rsyslog.pwd.getpwnam')
    def test_returns_false_when_not_writable(
        self, mock_getpwnam, mock_getgrnam, mock_exists,
        mock_makedirs, mock_access, mock_chown, mock_chmod
    ):
        """Should return failure when directory is not writable."""
        mock_exists.return_value = True
        mock_access.return_value = False  # Not writable
        mock_getpwnam.return_value = mock.Mock(pw_uid=1001)
        mock_getgrnam.return_value = mock.Mock(gr_gid=1001)
        
        result = ensure_spool_directory('/var/spool/rsyslog/test')
        
        self.assertFalse(result['status'])
        self.assertIn('not writable', result['message'])
    
    @mock.patch('toolkit.system.rsyslog.os.chmod')
    @mock.patch('toolkit.system.rsyslog.os.chown')
    @mock.patch('toolkit.system.rsyslog.os.access')
    @mock.patch('toolkit.system.rsyslog.os.makedirs')
    @mock.patch('toolkit.system.rsyslog.os.path.exists')
    @mock.patch('toolkit.system.rsyslog.grp.getgrnam')
    @mock.patch('toolkit.system.rsyslog.pwd.getpwnam')
    def test_uses_custom_owner_and_mode(
        self, mock_getpwnam, mock_getgrnam, mock_exists,
        mock_makedirs, mock_access, mock_chown, mock_chmod
    ):
        """Should apply custom owner/group/mode when provided."""
        mock_exists.return_value = False
        mock_access.return_value = True
        mock_getpwnam.return_value = mock.Mock(pw_uid=1005)
        mock_getgrnam.return_value = mock.Mock(gr_gid=1005)
        
        result = ensure_spool_directory(
            '/var/spool/rsyslog/test',
            owner='custom_user',
            group='custom_group',
            mode=0o700
        )
        
        self.assertTrue(result['status'])
        mock_getpwnam.assert_called_with('custom_user')
        mock_getgrnam.assert_called_with('custom_group')
        mock_chmod.assert_called()
        # Verify the mode was passed
        chmod_call_args = mock_chmod.call_args
        self.assertEqual(chmod_call_args[0][1], 0o700)


class CheckSpoolDirectoryTaskTest(TestCase):
    """Tests for check_spool_directory vultured task wrapper."""
    
    @mock.patch('toolkit.system.rsyslog.ensure_spool_directory')
    def test_logs_success(self, mock_ensure):
        """Should log success message."""
        mock_ensure.return_value = {'status': True, 'message': 'Success'}
        mock_logger = mock.Mock()
        
        result = check_spool_directory(mock_logger, '/var/spool/test')
        
        self.assertTrue(result['status'])
        mock_logger.info.assert_called_once()
    
    @mock.patch('toolkit.system.rsyslog.ensure_spool_directory')
    def test_logs_failure(self, mock_ensure):
        """Should log error on failure."""
        mock_ensure.return_value = {'status': False, 'message': 'Failed'}
        mock_logger = mock.Mock()
        
        result = check_spool_directory(mock_logger, '/var/spool/test')
        
        self.assertFalse(result['status'])
        mock_logger.error.assert_called_once()
    
    @mock.patch('toolkit.system.rsyslog.ensure_spool_directory')
    def test_handles_exception(self, mock_ensure):
        """Should catch exceptions and return failure."""
        mock_ensure.side_effect = Exception("Unexpected error")
        mock_logger = mock.Mock()
        
        result = check_spool_directory(mock_logger, '/var/spool/test')
        
        self.assertFalse(result['status'])
        self.assertIn('Unexpected error', result['message'])
        mock_logger.error.assert_called()
