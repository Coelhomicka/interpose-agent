"""Run the broker as an operating-system service under its own identity.

In development the broker runs as the current user, so anything else running as
that user (an agent included) can read the vault from disk. Installed as a
service, the broker runs as the Windows virtual account ``NT SERVICE\\Interpose``:
the vault and its master key live in a folder only that account (and SYSTEM and
elevated administrators) can open, and the code it runs lives under Program
Files, where the user cannot change it. Agents keep talking to the same loopback
proxy; they just have nothing on disk to read anymore.
"""

SERVICE_NAME = "Interpose"
SERVICE_ACCOUNT = f"NT SERVICE\\{SERVICE_NAME}"
SERVICE_DISPLAY_NAME = "Interpose credential broker"
