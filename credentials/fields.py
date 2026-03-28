from django.db import models
from .encryption import encrypt_value, decrypt_value


class EncryptedTextField(models.TextField):
    """
    Stores values encrypted (Fernet) in the database.
    Transparently encrypts on write and decrypts on read.
    Empty strings are stored as-is (no encryption overhead for blank fields).
    """

    def from_db_value(self, value, expression, connection):
        if value is None or value == '':
            return value
        return decrypt_value(value)

    def get_prep_value(self, value):
        if not value:
            return value
        # Already looks encrypted (Fernet tokens start with 'gAAAAA')
        # Don't double-encrypt if the value came from the DB unchanged.
        # We detect this by checking: if it looks like a Fernet token AND
        # decrypting it succeeds, it's already encrypted.
        if isinstance(value, str) and value.startswith('gAAAAA'):
            from .encryption import decrypt_value
            if decrypt_value(value):
                return value
        return encrypt_value(value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        return name, path, args, kwargs
