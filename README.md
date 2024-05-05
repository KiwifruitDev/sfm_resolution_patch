# Viewport Resolution Patch
Patch SFM to use custom viewport resolutions.

[View Workshop submission](https://steamcommunity.com/sharedfiles/filedetails/?id=3239809408)

## Installation
**It is recommended to install this script from the Steam Workshop.**
This script may be updated occasionally.

For advanced (-nosteam) users only, choose an alternate installation method:

- Clone the [GitHub repository](https://github.com/KiwifruitDev/sfm_resolution_patch) into your SourceFilmmaker/game/ directory and add the folder to your gameinfo.txt file.
- Download the [script](https://github.com/KiwifruitDev/sfm_resolution_patch/blob/main/scripts/sfm/mainmenu/kiwifruitdev/resolution_patch.py) as a raw *.py file and place it into SourceFilmmaker/game/usermod/scripts/sfm/mainmenu/kiwifruitdev/ (create the folders if they don't exist).

## Usage
This script will patch ifm.dll to allow custom resolutions and does not require running each time you launch SFM.

- Launch Source Filmmaker.
- At the top, click Scripts > kiwifruitdev > resolution patch.
- Please read the warning before clicking OK.
- Click OK, it will ask you to save your session first.
- SFM will be patched and restarted.
- After restarting, check Help > About Source Filmmaker [Beta]
- If "KiwifruitDev RPatch" appears in the dialog, the patch was successful.
- Close SFM and set -sfm_width and -sfm_height launch options through Steam.
- Launch SFM and enjoy your custom viewport resolution.

Once patched, -sfm_resolution will no longer work. Use -sfm_width and -sfm_height instead.

## Known Issues
Windows must be installed in C:\Windows for the script to be able to restart SFM.

It is very rare for this to be an issue, but if it is, you can manually restart SFM.

Testing is very limited, so if you encounter any issues, please report them on the [issues page](https://github.com/KiwifruitDev/sfm_resolution_patch/issues).

## Notes
This script saves a backup of the original ifm.dll in the same directory as the script.

If you encounter any issues, you can restore the original ifm.dll by renaming the backup to ifm.dll.

It is located in SourceFilmmaker/game/bin/tools and has a timestamp in the filename.

Also, this script writes files in order to apply the patch. After the patch is applied, these files are deleted.

## Support Me
https://ko-fi.com/kiwifruitdev

## Credits
This script uses code from the following sources:

- https://github.com/meunierd/python-ips (No license specified)
- https://github.com/nleseul/ips_util (The Unlicense)

## License
This project is licensed under the MIT License.
