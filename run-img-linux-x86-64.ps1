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

$ErrorActionPreference = "Stop";
$root = (Get-Location).Path;
$out = "$root/out";
$efiImg = "$out/efi.img";

& "$root/build-img-linux.ps1";
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed.";
    return $LASTEXITCODE;
}

# YMMV; you need to have QEMU installed with EFI on the below path. On Debian, the following command was used for QEMU installation:
# sudo apt install qemu-utils qemu-system-x86 qemu-system-gui qemu-efi
qemu-system-x86_64 -bios "/usr/share/ovmf/OVMF.fd" -cdrom $efiImg;
