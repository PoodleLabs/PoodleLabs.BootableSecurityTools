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
Write-Progress "Churning Tests";
while ($true) {
    cargo test --release --quiet;
    # cargo test --release --quiet -- --nocapture;
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed.";
        return $LASTEXITCODE;
    }

    Write-Output "All Tests Passed";
}
