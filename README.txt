====================================================
  ZERO-TRUST VAULT  v1.0.0
  Local Windows Hello password manager for Chrome
====================================================

Everything is stored on YOUR computer only.
No cloud. No account. No subscription.
Your passwords are locked with Windows Hello
(fingerprint, face scan, or PIN).

----------------------------------------------------
  REQUIREMENTS
----------------------------------------------------

  - Windows 10 or 11
  - Google Chrome (version 127 or newer)
  - Windows Hello must be set up
    (Settings -> Accounts -> Sign-in options)

----------------------------------------------------
  INSTALLATION  (two steps, takes ~2 minutes)
----------------------------------------------------

STEP 1: Load the extension in Chrome
-------------------------------------

  1. Open Chrome and go to:   chrome://extensions
  2. Turn on "Developer mode" (toggle in the top-right)
  3. Click "Load unpacked"
  4. Browse to this folder and select the "extension" folder
  5. The extension appears. Copy its ID — it looks like:
       abcdefghijklmnopqrstuvwxyz123456
     (32 lowercase letters, shown under the extension name)

  Keep this ID handy, you need it in Step 2.


STEP 2: Install the native host
---------------------------------

  1. Open the Start menu, search for "PowerShell", right-click
     it and choose "Run as administrator"

  2. In the PowerShell window, run this command
     (replace YOUR-EXTENSION-ID with what you copied):

       powershell -ExecutionPolicy Bypass -File "C:\path\to\install\install.ps1" -ExtensionId YOUR-EXTENSION-ID

     TIP: You can drag the install.ps1 file from the "install"
     folder into the PowerShell window instead of typing the path.

  3. Click Yes if Windows asks for permission (UAC prompt)

  4. Go back to chrome://extensions and click the
     reload button (circular arrow) on Zero-Trust Vault

That's it. The vault icon will appear in your Chrome toolbar
(click the puzzle piece icon to find it and pin it).

----------------------------------------------------
  HOW TO USE
----------------------------------------------------

UNLOCK
  Click the Zero-Trust Vault icon in Chrome's toolbar.
  Click "Unlock with Windows Hello" and approve with your
  fingerprint, face, or PIN.

SAVE A PASSWORD
  1. Unlock the vault
  2. Navigate to the website you want to save
  3. Click the vault icon -> "Save credential"
  4. Enter your username and password, click Save
  5. Approve with Windows Hello

FILL A PASSWORD
  1. Unlock the vault
  2. Navigate to the login page
  3. Click the vault icon -> click "Fill" next to the credential
  4. Approve with Windows Hello (required for every fill)
  5. Your username and password are filled automatically

The vault locks itself automatically after 15 minutes
of inactivity (you can change this in Settings).

----------------------------------------------------
  AUTOMATIC BACKUPS
----------------------------------------------------

Your vault is backed up automatically every day to:
  - Your Documents folder  (ZeroTrustVault-Backups)
  - Any USB drive you have plugged in

Backups are encrypted the same way as the vault itself.
To enable automatic backups, run in PowerShell:

  powershell -ExecutionPolicy Bypass -File "install\install-backup-task.ps1"

To restore from a backup, run:

  powershell -ExecutionPolicy Bypass -File "install\restore-vault.ps1" -List

----------------------------------------------------
  TROUBLESHOOTING
----------------------------------------------------

"Specified native messaging host not found"
  -> Re-run install.ps1 with the correct extension ID
  -> Reload the extension in chrome://extensions

"Fill blocked: exact origin mismatch"
  -> The credential was saved for a different URL.
     Save a new credential for this exact site.

Windows Hello keeps asking every time I fill
  -> This is intentional security design.
     Each fill requires a fresh approval.

Extension shows "!!" badge in red
  -> Extension files were modified after installation.
     Uninstall and reinstall from a trusted copy.

----------------------------------------------------
  UNINSTALL
----------------------------------------------------

  powershell -ExecutionPolicy Bypass -File "install\uninstall.ps1"

  Then go to chrome://extensions and remove Zero-Trust Vault.

----------------------------------------------------
