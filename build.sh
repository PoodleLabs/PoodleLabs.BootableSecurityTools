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
set -e

root="$(dirname -- ${BASH_SOURCE[0]})"
out="$root/out"

if [ -d "$out" ]; then
    rm -rf "$out"
fi

boot="$out/EFI/BOOT"
mkdir -p "$boot"

echo "Running Tests..."
cargo test --release

function build_target() {
    echo "Building for $2 architecture..."
    cargo build -r --target $1

    echo "Copying EFI file for $2 architecture..."
    cp "$root/target/$1/release/bst.efi" "$boot/$3.EFI"
}

build_target "aarch64-unknown-uefi" "AARCH64" "BOOTAA64"
build_target "i686-unknown-uefi" "IA32" "BOOTIA32"
build_target "x86_64-unknown-uefi" "x64" "BOOTx64"
echo "Successfully built."
