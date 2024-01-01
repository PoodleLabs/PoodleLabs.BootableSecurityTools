#!/bin/bash
# Poodle Labs' Bootable Security Tools (BST)
# Copyright (C) 2023 Isaac Beizsley
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
set -eE

root="$(dirname -- ${BASH_SOURCE[0]})"
out="$root/out"
efi="$out/EFI"

eval "$root/build.sh"

echo "Preparing EFI image filesystem..."
efi_img="$out/efi.img"
mnt="$out/mnt"
mkdir "$mnt"

function remove_mnt_dir() {
    rm -rf "$mnt"
}

# Error will delete mnt directory.
trap "remove_mnt_dir" ERR

truncate -s 100M "$efi_img"

function remove_efi_img() {
    rm "$efi_img"
}

# Error will delete mnt directory and efi image.
trap "remove_mnt_dir & remove_efi_img" ERR

sudo mkfs.vfat "$efi_img"

echo "Mounting EFI image..."
sudo mount -oloop "$efi_img" "$mnt"

function unmount_mnt_dir() {
    sudo umount "$mnt"
}

# Successful exit will unmount image then delete mnt directory.
trap "unmount_mnt_dir && remove_mnt_dir" EXIT

# Error will unmount image then delete mnt directory and efi image.
trap "unmount_mnt_dir && (remove_mnt_dir & remove_efi_img)" ERR

echo "Copying EFI files..."
sudo cp -rf "$efi" "$mnt"

echo "EFI image built successfully."
exit 0
