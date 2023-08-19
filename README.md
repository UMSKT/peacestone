# peacestone

> The antithesis of the WARBIRD obfuscator (Vista-7 only).

Join our [Zulip chat](https://umskt.zulipchat.com/) to discuss findings made with this tool!

## Installation/Usage

1. Run `pip install --user -r requirements.txt`
2. Download rootfs [from here](https://files.catbox.moe/hzmla1.7z). Extract `rootfs/Windows` to the `peacestone` folder.
3. Place the program to be deobfuscated in the `peacestone` folder.
4. Place the corresponding PDB file for the program in the same folder. Ensure the PDB has the same name as the program.
5. Run `python peacestone.py <program to deobfuscate>`
6. Enjoy!

## Notes

This program has only been tested on files from Windows Server 2003 KMS Server version 1.0. If you encounter any bugs with other files, feel free to report them.

## Special Thanks

 - Guy who compiled every single activation library into `sppsvc.exe` for no reason
 - Guy who forgot to remove WARBIRD symbols and encrypted function symbols from the public PDB
 - Guy(s) who left the PDBs up for 17 years
