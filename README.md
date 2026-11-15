# AccountSwitcher
Switch between multiple accounts

## Warning
_**User tokens can be used for using someone else's account without their knowledge.
To prevent token abuse BetterDiscord staff is not supporting account switchers. If something isn't working ask me and not in BetterDiscord support servers.<br>
Also you shouldn't give your token to anybody. If you do they can access your account and can do everything you don't need a verification with the password.<br>
If you accidentally shared your token you can change your password or enable 2FA and you will get a new token. But don't forget to change the token in your settings.**_

## Security
Saved tokens are always encrypted (AES-256-GCM, key from your password via PBKDF2). The plugin makes no network requests and downloads no code. Accounts saved with versions < 2.0.0 are discarded and must be saved again.

## Usage
### Adding accounts
Log in to the account you want to save. Then open the plugin settings and click the `Save Account` button. To save another account, click the `Log out` button in the plugin settings and then log in to the other account and repeat this procedure.
**If you change your password or you enable/disable 2FA your account gets a new token. The old one will no longer be working.**

### Switching accounts
To switch between account you only need to press `Alt` and a number key (NOT NUMPAD!). With `1` you will switch to the account labeled as `Account 1` in the settings. `2` is `Account 2` etc. `0` is `Account 10`.

You can also middle click your avatar in the quick settings field at the bottom. A popup will appear with the accounts you have set in the settings (and their avatar, but for some people it doesn't seem to work). Just click the account you want to switch to and everything should work fine.

## Download
[Click here and then press Ctrl+S to download](https://raw.githubusercontent.com/POLIMOfficiel/AccountSwitcherpolimo/main/AccountSwitcher.plugin.js)
