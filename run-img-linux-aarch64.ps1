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
$efiFd = "$out/EFI.fd";
$efiImg = "$out/efi.img";

& "$root/build-img-linux.ps1";
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed.";
    return $LASTEXITCODE;
}

if (Test-Path -Path $efiFd) {
    Remove-Item -Force -Path $efiFd;
}

truncate -s 64M $efiFd;
if ($LASTEXITCODE -ne 0) {
    Write-Error "EFI firmware image file creation failed.";
    return $LASTEXITCODE;
}

dd if="/usr/share/qemu-efi-aarch64/QEMU_EFI.fd" of=$efiFd conv=notrunc;

# YMMV; you need to have QEMU installed with EFI on the below path. On Debian, the following command was used for QEMU installation:
# sudo apt install qemu-utils qemu-system-arm qemu-system-gui qemu-efi-aarch64
qemu-system-aarch64 -machine virt -cpu max -drive "if=pflash,format=raw,file=$efiFd" -net none -nographic -cdrom $efiImg;
