from django.db import models
from twofactor.util import encrypt_value, decrypt_value, get_google_url
from twofactor.util import random_seed
from base64 import b32encode
from socket import gethostname

import googauth


class UserAuthToken(models.Model):
    user = models.OneToOneField("auth.User")
    encrypted_seed = models.CharField(max_length=120)  # fits 16b salt+40b seed

    created_datetime = models.DateTimeField(
        verbose_name="created", auto_now_add=True)
    updated_datetime = models.DateTimeField(
        verbose_name="last updated", auto_now=True)

    def save( self ):
        self.encrypted_seed = encrypt_value( random_seed() )

    def check_auth_code(self, auth_code):
        """
        Checks whether `auth_code` is a valid authentication code for this
        user, at the current time.
        """

        secret_key = b32encode( decrypt_value( self.encrypted_seed ) )
        val = googauth.verify_time_based( secret_key,
                                          str( auth_code ), window=5 )
        return val != None

    def google_url(self, name=None):
        """
        The Google Charts QR code version of the seed, plus an optional
        name for this (defaults to "username@hostname").
        """
        if not name:
            username = self.user.username
            hostname = gethostname()
            name = "%s@%s" % (username, hostname)

        return get_google_url(
            decrypt_value(self.encrypted_seed),
            name
        )

    def b32_secret(self):
        """
        The base32 version of the seed (for input into Google Authenticator
        and similar soft token devices.
        """
        return b32encode(decrypt_value(self.encrypted_seed))
