"""Defines the exceptions of the misakoba_mail package."""


class MisakobaMailError(Exception):
    """Base class for application-specific errors."""


class MissingRequiredConfigValueError(MisakobaMailError):
    """Error for MissingConfigValue."""


class InvalidMessageToError(MisakobaMailError):
    """Error when the Message's 'to' Header is invalid."""


class InvalidEnvironmentConfigValueError(MisakobaMailError):
    """Error for invalid config values derived from the environment."""
    def __init__(self, config_value_name, value):
        super().__init__()
        self.config_value_name = config_value_name
        self.value = value

    def __str__(self):
        return (f'Invalid {self.config_value_name} value {self.value!r} '
                f'specified.')


class InvalidLoggingLevelError(InvalidEnvironmentConfigValueError):
    """Error if the 'LOGGING_LEVEL' config value is invalid."""

    def __init__(self, value):
        super().__init__('LOGGING_LEVEL', value)


class InvalidProxyFixXForError(InvalidEnvironmentConfigValueError):
    """Error if the 'PROXY_FIX_X_FOR' config value is invalid."""

    def __init__(self, value):
        super().__init__('PROXY_FIX_X_FOR', value)
