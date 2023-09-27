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
$efi = "$out/EFI";

& "$root/build.ps1";
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed.";
    return $LASTEXITCODE;
}

$efiImg = "$out/efi.img";
if (Test-Path -Path $efiImg) {
    Remove-Item -Force -Path $efiImg;
}

$mnt = "$out/mnt";
if (Test-Path -Path $mnt) {
    Remove-Item -Force -Recurse -Path $mnt;
}

New-Item -Path $mnt -ItemType "Directory";
truncate -s 100M $efiImg;
if ($LASTEXITCODE -ne 0) {
    Write-Error "EFI image file creation failed.";
    return $LASTEXITCODE;
}

sudo mkfs.vfat $efiImg;
if ($LASTEXITCODE -ne 0) {
    Write-Error "mkfs.vfat failed.";
    return $LASTEXITCODE;
}

sudo mount -oloop $efiImg $mnt;
if ($LASTEXITCODE -ne 0) {
    Write-Error "Mounting EFI image failed.";
    return $LASTEXITCODE;
}

try {
    sudo cp -rf $efi $mnt;
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Copying EFI folder failed.";
        return $LASTEXITCODE;
    }
}
finally {
    sudo umount $mnt;
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Unmounting EFI image failed; run 'sudo unmount ./out/mnt'.";
    }
}

Remove-Item -Force -Recurse -Path $mnt;
