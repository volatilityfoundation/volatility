# Volatility
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import sys
import shutil
import subprocess


def run_cmd(args, output_file = None):
    """Run a command through subprocess. 

    @param args: a list of arguments 
    @param output_file: the process's stdout should be redirected here
    """

    print "Running command: {0}".format(" ".join(args))
    if output_file:
        stdout_handle = open(output_file, "w")
    else:
        stdout_handle = subprocess.PIPE
    p = subprocess.Popen(args, stdout = stdout_handle, stderr = subprocess.STDOUT)
    p.wait()
    if output_file:
        stdout_handle.close()
    print "  Retcode: {0}".format(p.returncode)


def generate_profile(temp_dir, volatility_dir, profile_dir, profile, in_local_library = False):
    """Generate a profile. 

    @param temp_dir: temporary working directory
    @param volatility_dir: path to volatility installation 
    @param profile_dir: where to put finished zip profiles
    @param profile: tuple of information for building the profile
    @param in_local_library: is this profile's KDK in /Library/Developer?
    """

    (full_path, arch, osx_name, version, build) = profile

    kdk_root = full_path

    if not in_local_library:
        kdk_root = "/Volumes/KernelDebugKit/"
        # This lets us mount the DMG without a GUI license Y/N prompt
        args = ["/usr/bin/hdiutil", "convert", "-quiet", full_path,
                "-format", "UDTO", "-o", os.path.join(temp_dir, "test")]
        run_cmd(args)

        args = ["/usr/bin/hdiutil", "attach", "-quiet", "-nobrowse", "-noverify",
                "-noautoopen", "-mountpoint", kdk_root + "", os.path.join(temp_dir, "test.cdr")]
        run_cmd(args)

    dwarf_info = os.path.join(temp_dir, "dwarf.txt")
    # handle the change in filenames in 10.10
    if os.path.isdir(kdk_root + "kernel.dSYM"):
        kernel = kdk_root + "kernel.dSYM"
    else:
        kernel = kdk_root + "mach_kernel.dSYM"
    args = ["/usr/bin/dwarfdump", "-arch", arch, "-i", kernel]
    run_cmd(args, output_file = dwarf_info)

    convert_py = os.path.join(volatility_dir, "tools/mac/convert.py")
    new_dwarf = dwarf_info + ".conv"
    args = ["/usr/bin/python", convert_py, dwarf_info, new_dwarf]
    run_cmd(args)

    vtypes_file = new_dwarf + ".vtypes"
    args = ["/usr/bin/python", convert_py, new_dwarf]
    run_cmd(args, output_file = vtypes_file)

    symbol_file = dwarf_info + ".symbol.dsymutil"
    # handle the change in filenames in 10.10
    if os.path.isfile(kdk_root + "mach_kernel"):
        kernel = kdk_root + "mach_kernel"
    else:
        kernel = kdk_root + "kernel"
    args = ["/usr/bin/dsymutil", "-s", "-arch", arch, kernel]
    run_cmd(args, output_file = symbol_file)

    profile_name = osx_name + "_" + version
    profile_name += "_" + build
    profile_name += ".zip"

    zip_file = os.path.join(profile_dir, profile_name)
    args = ["/usr/bin/zip", zip_file, symbol_file, vtypes_file]
    run_cmd(args)

    if not in_local_library:
        args = ["/usr/bin/hdiutil", "detach", kdk_root]
        run_cmd(args)

    shutil.rmtree(temp_dir)
    os.mkdir(temp_dir)


def main():
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print "Usage: {0} [optional kit dir] <temp dir> <vol dir> <profile dir>".format(sys.argv[0])
        return

    profile_runs = []

    if len(sys.argv) == 5:
        # User specified a directory containing downloaded pre-10.10 KDKs
        kit_dir = sys.argv[1]
        temp_dir = sys.argv[2]
        vol_dir = sys.argv[3]
        profile_dir = sys.argv[4]
    else:
        # User didn't specify a kit dir; below, we will assume /Library/Developer
        kit_dir = ""
        temp_dir = sys.argv[1]
        vol_dir = sys.argv[2]
        profile_dir = sys.argv[3]

    # First, look in <kit dir> for .dmg files that contain unbundled
    # kernel debug kits. Usually these are pre-10.10.
    if kit_dir:
        for kit in os.listdir(kit_dir):
            try:
                full_path = os.path.join(kit_dir, kit)
                file_part = os.path.splitext(kit[len("kernel_debug_kit_"):])[0]
                (version, build) = file_part.split("_")
            except ValueError:
                continue

            if version.startswith("10.5"):
                osx_name = "Leopard"
                profile_runs.append(
                    (full_path, "i386", osx_name, version, build))
            elif version.startswith("10.6"):
                osx_name = "SnowLeopard"
                profile_runs.append(
                    (full_path, "i386", osx_name, version, build))
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))
            elif version.startswith("10.7"):
                osx_name = "Lion"
                profile_runs.append(
                    (full_path, "i386", osx_name, version, build))
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))
            elif version.startswith("10.8"):
                osx_name = "MountainLion"
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))
            elif version.startswith("10.9"):
                osx_name = "Mavericks"
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))
            elif version.startswith("10.10"):
                osx_name = "Yosemite"
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))
            elif version.startswith("10.11"):
                osx_name = "ElCapitan"
                profile_runs.append(
                    (full_path, "x86_64", osx_name, version, build))

    for profile in profile_runs[:]:
        generate_profile(temp_dir = temp_dir,
                         volatility_dir = vol_dir,
                         profile_dir = profile_dir,
                         profile = profile)
        profile_runs.remove(profile)

    # Now look in the local Apple developer Library for installed KDKs. Pre 10.10
    # KDKs don't have the .pkg installer, so we start at 10.10.
    kdk_root_dir = "/Library/Developer/KDKs"
    for kit in os.listdir("/Library/Developer/KDKs/"):
        try:
            full_path = os.path.join(
                kdk_root_dir, kit, "System/Library/Kernels/")
            file_part = os.path.splitext(kit[len("KDK_"):])[0]
            (version, build) = file_part.split("_")
        except ValueError:
            continue
        if version.startswith("10.10"):
            osx_name = "Yosemite"
            profile_runs.append(
                (full_path, "x86_64", osx_name, version, build))
        elif version.startswith("10.11"):
            osx_name = "ElCapitan"
            profile_runs.append(
                (full_path, "x86_64", osx_name, version, build))
        elif version.startswith("10.12"):
            osx_name = "Sierra"
            profile_runs.append(
                (full_path, "x86_64", osx_name, version, build))

    for profile in profile_runs:
        generate_profile(temp_dir = temp_dir,
                         volatility_dir = vol_dir,
                         profile_dir = profile_dir,
                         profile = profile,
                         in_local_library = True)

    return

if __name__ == "__main__":
    main()
