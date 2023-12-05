# Poodle Labs' Bootable Security Tools

**WARNING: THESE TOOLS ARE NOT YET READY FOR PRODUCTION USE. BUGS ALMOST CERTAINLY EXIST. SECURITY FLAWS MAY EXIST. USE OUTSIDE OF A DEVELOPMENT & TESTING CONTEXT AT YOUR OWN RISK.**

This repository contains UEFI-bootable security-related tools designed to be used on an airgapped device, wrapped in a text-based user interface.

For a list of currently implemented and planned additional functionalities, visit the [discussions section](https://github.com/PoodleLabs/PoodleLabs.BST/discussions/2).

## What kinds of tools?

The [discussions section](https://github.com/PoodleLabs/PoodleLabs.BST/discussions/2) contains a detailed list of features which have been currently implemented, as well as planned features.

In broad terms, the most interesting functionalities, and their states (bear in mind 'done' means functional, not final) are:

### Hashing

- RIPEMD160 - **DONE**
- SHA256 - **DONE**
- SHA5512 - **DONE**
- HMAC - **DONE (All three above hashing algos)**
- PBKDF2 - **DONE (All three above hashing algos)**

Other hashing algorithms and 'attachment' schemes could be considered.

### Manual Entropy Collection

- Coinflips - **DONE (With Von Neumann bias correction)**
- D4 - **DONE (With Von Neumann bias correction)**
- D6 - **DONE**
- D8 - **DONE (With Von Neumann bias correction)**
- D10 - **DONE**
- D12 - **DONE**
- D16 - **DONE (With Von Neumann bias correction)**
- D20 - **DONE**
- D100 - **DONE**
- Externally Sourced Bytes - **DONE (With Von Neumann bias correction)**
- CSPRNG - **NOT STARTED**
- Deck of Cards - **NOT STARTED**

### Entropy Mnemonics

- BIP 39 - **DONE**
- Electrum - **DONE**
- Diceware - **NOT STARTED**

### Asymmetric Encryption

- Private & Public Key Derivation on secp256k1 - **DONE**
- ECDSA on secp256k1 - **NOT STARTED**
- ECIES on secp256k1 - **NOT STARTED**

Additional curves are likely to be supported in the future, maybe also non-EC asymmetric schemes.

### Symmetric Encryption

- AES(128, 192, 256) Encryption - **NOT STARTED**
- AES(128, 192, 256) Decryption - **NOT STARTED**

Other schemes could be considered.

### BIP 32 HD Wallets

- BIP 39 Seed Derivation - **DONE**
- Electrum SVS Seed Derivation - **DONE**
- BIP 32 Master Key Derivation - **DONE**
- BIP 32 Extended Public Key Derivation - **DONE**
- BIP 32 CKD - **DONE**

### Bitcoin Airgapped-Side Wallet

- Address Derivation - **NOT STARTED**
- PSBT Parsing & Display - **NOT STARTED**
- PSBT Signing - **NOT STARTED**

There are additional implemented and planned features, but the above are the big ones. Again, it'd be a good idea to check out the [discussions section roadmap](https://github.com/PoodleLabs/PoodleLabs.BST/discussions/2).

## What's interesting about *this* implementation of these tools?

All of the tools contained in this repository are written in Rust. The external runtime dependencies are Rust's `core` library (this is *not* the standard library), the Rust `alloc` crate, and the UEFI firmware running on the device you use.

That's it.

The idea is to absolutely minimize external dependencies for two primary reasons:
1. Ease of verification.
2. Minimal code to break.

These are _security oriented_ tools. It should be obvious why these two properties are highly desirable.

During development of the initial set of tools, it can be expected that the used surface area of the two external crates will grow. The goal is to bring this back down to the absolute minimum once all of the core planned features are in place. Yes, that means re-implementing basic structures like `Vec`, eventually. 

The goal is that, at some point, all of the code which is running when you use these tools is either firmware, or contained in this repository, written in the same language as everything else, in the same style as everything else, with no unused code to waste time for people who want to verify the code they are running.

## How do I use it?

You'll need to install Rustup, with the following targets installed:
- aarch64-unknown-uefi
- i686-unknown-uefi
- x86_64-unknown-uefi

The `build.ps1` powershell script can be used to run the tests, build all three targets, and dump them into the `out` folder. You can run the commands manually yourself and, of course, if you don't want to build all the targets, you don't have to.

Then you need to format a USB stick (or any other bootable media) with a FAT32 filesystem, and dump the `.efi` files in the directory `[MEDIA ROOT]/EFI/BOOT/*.efi`. You can just copy the `EFI` directory from `out` if you ran the powershell script.

If you didn't run the powershell script, the `.efi` files can be found at `target/[target]/release/bst.efi` after building the relevant target. You'll need to rename the EFI file; refer to the powershell script for the correct names for each target.

You should then be able to boot from that media.

### Some tips & tricks.

- To navigate, use the arrow keys and `ENTER`, or press `0-9` to select the corresponding list entry.
- In text/input boxes, you can use `PAGE UP` or `PAGE DOWN`, `HOME`, and `END`. The latter two can be modified with `CTRL`.
- Newlines from pressing `ENTER` in text boxes are `CR LF`, as that's the native newline for UEFI. `CTRL + ENTER` and `ALT + ENTER` can be used to insert a `LF` or `CR` by itself respectively, for hashing purposes.
- Numeric/byte inputs allow whitespace. This is handy for formatting.
- The difference between numbers and bytes is that numbers have leading zeroes trimmed off.
- Holding `ALT` when running a program, or opening a program list, will cause the list which contained it to be automatically closed if the program completes successfully.
- `CTRL + V` will prompt you to select a clipboard entry to paste if you're inputting data. You can paste text, bytes and numbers into any input, but when pasting text into a numeric/byte input, invalid characters will be dropped.
- `CTRL + [DIGIT]` will paste the corresponding clipboard entry, skipping the list select.
- `ESC` on the home screen will prompt you to confirm whether you want to exit BST. Yes will drop you back to the boot menu, or load your operating system, depending on what your firmware decides to do.
- The power options menu lets you shutdown, reboot, and reset. The difference between `Reboot` and `Reset` is defined by `UEFI`. `Reboot` is 'cold', and `Reset` is 'warm'.
- You can manage your clipboard entries in the `Clipboard Manager` in the `Utility Programs` menu.
- Read the output you're given.

### VM?

The included VM-related scripts are lazily written for my own use. I run Debian for development. You'll need QEMU w/ EFI and some other stuff set up. Check what the scripts do. I don't recommend the ARM one; I couldn't get it to work with a 'display', and outputting directly to the source terminal is janky; you'll probably need to play with the size of your terminal window to make the UI make any sense at all.

### I don't know how to do the steps above.

While I _may_ release binaries at some point, I'm not sure I want to. If I don't, eventually, the build and bootable media setup will be made easier. But this is a very early alpha development release, and I really, really don't want to encourage people to actually rely on these tools yet, so please, if you're intimidated by the above build & boot steps, wait for the tools to be ready for you.

### Hardware
For development, it really doesn't matter what hardware you use. It just needs to support UEFI. A VM is perfectly fine.

The ideal hardware which I envision these tools being run on is:
- [Corebooted](https://github.com/coreboot/coreboot)
- Airgapped, with wireless networking capabilities physically disabled/removed/never present in the first place.
- Has no internal storage.

The EFI images are loaded into memory, so you should be fine to remove the boot media once you're booted. Eventually, there will be file reads and writes, but the hope is that you'll be able to plug in media to read/write from when you need it, and unplug it as soon as you're done. The tools are aimed at the (in my opinion, rightly) paranoid.

If I had to recommend something more concrete, I would recommend an old Thinkpad. Something with a socketed CPU, which can be Corebooted and have the Intel ME disabled.

## External References
- [Electrum](https://github.com/spesmilo/electrum) or, more specifically [Electrum Seed Version System](https://electrum.readthedocs.io/en/latest/seedphrase.html)
- [Rust Lang Repository](https://github.com/rust-lang/rust/)
- [UEFI Specificatoins](https://uefi.org/specifications)
- [Bitcoin BIPS](https://github.com/bitcoin/bips)
- [FatFs](http://elm-chan.org/docs/fat_e.html)
