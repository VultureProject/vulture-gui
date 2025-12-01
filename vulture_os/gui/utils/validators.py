import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class AbsolutePathValidator:
    """
    Validator for absolute filesystem paths.
    Ensures the path:
    - Starts with /
    - Contains only allowed characters: [a-zA-Z0-9_./-]
    - Contains no path escape sequences like ../
    """

    ALLOWED_CHARS_PATTERN = re.compile(r'^[a-zA-Z0-9_./-]+$')
    PATH_ESCAPE_PATTERN = re.compile(r'(^|/)\.\.(/|$)')

    def __init__(self, message=None):
        self.message = message or _("Invalid absolute path format.")

    def __call__(self, value):
        if not value:
            raise ValidationError(_("Path cannot be empty."))

        # Must start with /
        if not value.startswith('/'):
            raise ValidationError(
                _("Path must be absolute (start with /)."),
                code='not_absolute'
            )

        # Check allowed characters only
        if not self.ALLOWED_CHARS_PATTERN.match(value):
            raise ValidationError(
                _("Path contains invalid characters. Allowed: a-z, A-Z, 0-9, _, ., /, -"),
                code='invalid_chars'
            )

        # No path escape (../)
        if self.PATH_ESCAPE_PATTERN.search(value):
            raise ValidationError(
                _("Path escape sequences (../) are not allowed."),
                code='path_escape'
            )

        return value


class SpoolDirectoryValidator(AbsolutePathValidator):
    """
    Validator for rsyslog spool/queue directories.
    Must be under /tmp or /var.
    """

    ALLOWED_ROOT_DIRS = ('/tmp/', '/var/')

    def __init__(self, message=None):
        super().__init__(message)
        self.message = message or _("Spool directory must be under /tmp or /var.")

    def __call__(self, value):
        # First validate as absolute path
        super().__call__(value)

        # Normalize path (ensure trailing slash for root dir comparison)
        normalized = value if value.endswith('/') else value + '/'

        # Must be under /tmp or /var
        if not any(normalized.startswith(root) for root in self.ALLOWED_ROOT_DIRS):
            raise ValidationError(
                _("Spool directory must be a subfolder of /tmp or /var."),
                code='invalid_root'
            )

        # Prevent using root dirs directly (must be subfolder)
        if normalized in self.ALLOWED_ROOT_DIRS:
            raise ValidationError(
                _("Cannot use /tmp or /var directly. Must be a subfolder."),
                code='is_root'
            )

        return value


# Convenience function for use in forms
def validate_spool_directory(value):
    """Validate spool directory path."""
    validator = SpoolDirectoryValidator()
    return validator(value)