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

if (Test-Path -Path $out) {
    Remove-Item -Recurse -Force -Path $out;
    if (Test-Path -Path $out) {
        Write-Error "Failed to remove old output.";
        return $LASTEXITCODE;
    }
}

New-Item -Path $out -ItemType "Directory";
$efi = "$out/EFI";
New-Item -Path $efi -ItemType "Directory";
$boot = "$efi/BOOT";
New-Item -Path $boot -ItemType "Directory";

Write-Progress "Running Tests";
cargo test --release;
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed.";
    return $LASTEXITCODE;
}

function Build-Target {
    param($target, $description, $efiFileName);
    Write-Progress "Building for $description architecture.";
    cargo build -r --target $target;
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Building for $description architecture failed."
        exit $LASTEXITCODE;
    }
    
    Write-Progress "Copying EFI file for $description architecture.";
    Copy-Item -Path "$root/target/$target/release/*.efi" -Force -Destination ("$boot/$efiFileName.EFI");
}

Build-Target "aarch64-unknown-uefi" "AARCH64" "BOOTAA64";
Build-Target "i686-unknown-uefi" "IA32" "BOOTIA32";
Build-Target "x86_64-unknown-uefi" "x64" "BOOTx64";
Write-Output "Successfully built.";
