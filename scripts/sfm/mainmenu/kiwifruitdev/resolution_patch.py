# SFM Viewport Resolution Patch
# Patch SFM to use custom viewport resolutions.
# https://github.com/KiwifruitDev/sfm_resolution_patch
# https://steamcommunity.com/sharedfiles/filedetails/?id=3239809408
# Based on https://github.com/KiwifruitDev/sfm_sample_script
# This software is licensed under the MIT License.
# Copyright (c) 2024 KiwifruitDev

import sfm
from vs import movieobjects
import sfmApp

import os
import sys
import traceback
import shutil
import itertools
import struct
import hashlib

from PySide import QtGui, QtCore, shiboken

try:
    sfm
except NameError:
    from sfm_runtime_builtins import *

ProductName = "Viewport Resolution Patch"
InternalName = "resolution_patch"

# https://github.com/meunierd/python-ips
# Modified by KiwifruitDev
# No license specified
def unpack_int(string, byteorder='big', signed=False):
    """Read an n-byte big-endian integer from a byte string."""
    if byteorder not in ('big', 'little'):
        raise ValueError("byteorder must be either 'big' or 'little'")
    if len(string) > 4:
        raise ValueError("string too large for conversion")
    if byteorder == 'big':
        endianness = '>'
    else:
        endianness = '<'
    if signed:
        format = 'i'
    else:
        format = 'I'
    (ret,) = struct.unpack_from(endianness + format, b'\x00' * (4 - len(string)) + string)
    return ret

# https://github.com/nleseul/ips_util
# Modified by KiwifruitDev
# The Unlicense
# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org>
class Patch:
    
    @staticmethod
    def load(filename):
        loaded_patch = Patch()

        with open(filename, 'rb') as file:

            header = file.read(5)
            if header != 'PATCH'.encode('ascii'):
                raise Exception('Not a valid IPS patch file!')
            while True:
                address_bytes = file.read(3)
                if address_bytes == 'EOF'.encode('ascii'):
                    break
                address = unpack_int(address_bytes, byteorder='big')

                length = unpack_int(file.read(2), byteorder='big')
                rle_count = 0
                if length == 0:
                    rle_count = unpack_int(file.read(2), byteorder='big')
                    length = 1
                data = file.read(length)

                if rle_count > 0:
                    loaded_patch.add_rle_record(address, data, rle_count)
                else:
                    loaded_patch.add_record(address, data)

            truncate_bytes = file.read(3)
            if len(truncate_bytes) == 3:
                loaded_patch.set_truncate_length(unpack_int(truncate_bytes, byteorder='big'))

        return loaded_patch

    @staticmethod
    def create(original_data, patched_data):
        # The heuristics for optimizing a patch were chosen with reference to
        # the source code of Flips: https://github.com/Alcaro/Flips

        patch = Patch()

        run_in_progress = False
        current_run_start = 0
        current_run_data = bytearray()

        runs = []

        if len(original_data) > len(patched_data):
            patch.set_truncate_length(len(patched_data))
            original_data = original_data[:len(patched_data)]
        elif len(original_data) < len(patched_data):
            original_data += bytes([0] * (len(patched_data) - len(original_data)))

            if original_data[-1] == 0 and patched_data[-1] == 0:
                patch.add_record(len(patched_data) - 1, bytes([0]))

        for index, (original, patched) in enumerate(zip(original_data, patched_data)):
            if not run_in_progress:
                if original != patched:
                    run_in_progress = True
                    current_run_start = index
                    current_run_data = bytearray([patched])
            else:
                if original == patched:
                    runs.append((current_run_start, current_run_data))
                    run_in_progress = False
                else:
                    current_run_data.append(patched)
        if run_in_progress:
            runs.append((current_run_start, current_run_data))

        for start, data in runs:
            if start == unpack_int(b'EOF', byteorder='big'):
                start -= 1
                data = bytes([patched_data[start - 1]]) + data

            grouped_byte_data = list([
                {'val': key, 'count': sum(1 for _ in group), 'is_last': False}
                for key,group in itertools.groupby(data)
            ])

            grouped_byte_data[-1]['is_last'] = True

            record_in_progress = bytearray()
            pos = start

            for group in grouped_byte_data:
                if len(record_in_progress) > 0:
                    # We don't want to interrupt a record in progress with a new header unless
                    # this group is longer than two complete headers.
                    if group['count'] > 13:
                        patch.add_record(pos, record_in_progress)
                        pos += len(record_in_progress)
                        record_in_progress = bytearray()

                        patch.add_rle_record(pos, bytes([group['val']]), group['count'])
                        pos += group['count']
                    else:
                        record_in_progress += bytes([group['val']] * group['count'])
                elif (group['count'] > 3 and group['is_last']) or group['count'] > 8:
                    # We benefit from making this an RLE record if the length is at least 8,
                    # or the length is at least 3 and we know it to be the last part of this diff.

                    # Make sure not to overflow the maximum length. Split it up if necessary.
                    remaining_length = group['count']
                    while remaining_length > 0xffff:
                        patch.add_rle_record(pos, bytes([group['val']]), 0xffff)
                        remaining_length -= 0xffff
                        pos += 0xffff

                    patch.add_rle_record(pos, bytes([group['val']]), remaining_length)
                    pos += remaining_length
                else:
                    # Just begin a new standard record.
                    record_in_progress += bytes([group['val']] * group['count'])

                if len(record_in_progress) > 0xffff:
                    patch.add_record(pos, record_in_progress[:0xffff])
                    record_in_progress = record_in_progress[0xffff:]
                    pos += 0xffff

            # Finalize any record still in progress.
            if len(record_in_progress) > 0:
                patch.add_record(pos, record_in_progress)

        return patch

    def __init__(self):
        self.records = []
        self.truncate_length = None

    def add_record(self, address, data):
        if address == unpack_int(b'EOF', byteorder='big'):
            raise RuntimeError('Start address {0:x} is invalid in the IPS format. Please shift your starting address back by one byte to avoid it.'.format(address))
        if address > 0xffffff:
            raise RuntimeError('Start address {0:x} is too large for the IPS format. Addresses must fit into 3 bytes.'.format(address))
        if len(data) > 0xffff:
            raise RuntimeError('Record with length {0} is too large for the IPS format. Records must be less than 65536 bytes.'.format(len(data)))

        record = {'address': address, 'data': data}
        self.records.append(record)

    def add_rle_record(self, address, data, count):
        if address == unpack_int(b'EOF', byteorder='big'):
            raise RuntimeError('Start address {0:x} is invalid in the IPS format. Please shift your starting address back by one byte to avoid it.'.format(address))
        if address > 0xffffff:
            raise RuntimeError('Start address {0:x} is too large for the IPS format. Addresses must fit into 3 bytes.'.format(address))
        if count > 0xffff:
            raise RuntimeError('RLE record with length {0} is too large for the IPS format. RLE records must be less than 65536 bytes.'.format(count))
        if len(data) != 1:
            raise RuntimeError('Data for RLE record must be exactly one byte! Received {0}.'.format(data))

        record = {'address': address, 'data': data, 'rle_count': count}
        self.records.append(record)

    def set_truncate_length(self, truncate_length):
        self.truncate_length = truncate_length

    def trace(self):
        print('''Start   End     Size   Data
------  ------  -----  ----''')
        for record in self.records:
            length = (record['rle_count'] if 'rle_count' in record else len(record['data']))
            data = ''
            if 'rle_count' in record:
                data = '{0} x{1}'.format(record['data'].hex(), record['rle_count'])
            elif len(record['data']) < 20:
                data = record['data'].hex()
            else:
                data = record['data'][0:24].hex() + '...'
            print('{0:06x}  {1:06x}  {2:>5}  {3}'.format(record['address'], record['address'] + length - 1, length, data))

        if self.truncate_length is not None:
            print()
            print('Truncate to {0} bytes'.format(self.truncate_length))

    def encode(self):
        encoded_bytes = bytearray()

        encoded_bytes += 'PATCH'.encode('ascii')

        for record in self.records:
            encoded_bytes += record['address'].to_bytes(3, byteorder='big')
            if 'rle_count' in record:
                encoded_bytes += (0).to_bytes(2, byteorder='big')
                encoded_bytes += record['rle_count'].to_bytes(2, byteorder='big')
            else:
                encoded_bytes += len(record['data']).to_bytes(2, byteorder='big')
            encoded_bytes += record['data']

        encoded_bytes += 'EOF'.encode('ascii')

        if self.truncate_length is not None:
            encoded_bytes += self.truncate_length.to_bytes(3, byteorder='big')

        return encoded_bytes

    def apply(self, in_data):
        out_data = bytearray(in_data)

        for record in self.records:
            if record['address'] >= len(out_data):
                out_data += bytes([0] * (record['address'] - len(out_data) + 1))

            if 'rle_count' in record:
                out_data[record['address'] : record['address'] + record['rle_count']] = b''.join([record['data']] * record['rle_count'])
            else:
                out_data[record['address'] : record['address'] + len(record['data'])] = record['data']

        if self.truncate_length is not None:
            out_data = out_data[:self.truncate_length]

        return out_data

class PatchWindow(QtGui.QDialog):
    def __init__(self):
        super(PatchWindow, self).__init__()
        self.initUI()

    def initUI(self):
        # Show user information about the patch
        self.setWindowTitle(ProductName + ": Information")
        baselayout = QtGui.QFormLayout(self)
        self.setLayout(baselayout)
        info1 = QtGui.QLabel("This script will patch your SFM installation to allow for custom viewport resolutions.")
        info2 = QtGui.QLabel("A backup of \"ifm.dll\" will be created in the same directory as the original.")
        info3 = QtGui.QLabel("SFM will require a restart after the patching process is complete.")
        info4 = QtGui.QLabel("The -sfm_resolution option will no longer function after this patch.")
        info5 = QtGui.QLabel("Instead, you must use -sfm_width and -sfm_height to set the viewport resolution.")
        info6 = QtGui.QLabel("This can be done through the Steam launch options for SFM.")
        info7 = QtGui.QLabel("When you're ready, click the button below to begin the patching process.")
        info8 = QtGui.QLabel("Note: You only need to run this script once.")
        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok | QtGui.QDialogButtonBox.Cancel, QtCore.Qt.Horizontal, self)
        baselayout.addRow(info1)
        baselayout.addRow(info2)
        baselayout.addRow(info3)
        baselayout.addRow(QtGui.QLabel(""))
        baselayout.addRow(info4)
        baselayout.addRow(info5)
        baselayout.addRow(info6)
        baselayout.addRow(QtGui.QLabel(""))
        baselayout.addRow(info7)
        baselayout.addRow(info8)
        baselayout.addRow(QtGui.QLabel(""))
        baselayout.addRow(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.close)
    
    def accept(self):
        # Ask user to save their session
        sfmApp.CloseDocument(False)
        if sfmApp.HasDocument():
            return
        self.createPatch()

    def cleanUp(self):
        try:
            # Delete any existing files
            if os.path.exists(self.ips_patch_path):
                os.remove(self.ips_patch_path)
            if os.path.exists(self.ifm_prefix + self.ifm_temp + self.ifm_suffix):
                os.remove(self.ifm_prefix + self.ifm_temp + self.ifm_suffix)
            if os.path.exists(self.ifm_prefix + self.ifm_patched + self.ifm_suffix):
                os.remove(self.ifm_prefix + self.ifm_patched + self.ifm_suffix)
            if os.path.exists(self.restart_bat):
                os.remove(self.restart_bat)
        except Exception as e:
            ErrorMessageBox("An error occured while cleaning up.", e)
            self.close()

    def finish(self):
        self.cleanUp()
        self.close()

    def compareChecksum(self, oldfile):
        try:
            # Check if ifm.dll has been modified
            with open(oldfile, "rb") as f:
                checksum = hashlib.md5(f.read()).hexdigest()
            if checksum != self.ifm_checksum:
                ShowMessageBox("The checksum of ifm.dll has changed. Please restore the original file before patching.\n\nChecksum: %s\nExpected: %s" % (checksum, self.ifm_checksum), Critical)
                self.finish()
                return False
        except Exception as e:
            ErrorMessageBox("An error occured while comparing checksums.", e)
            self.finish()
        return True
        
    def createPatch(self):
        self.cleanUp()
        try:
            # Create IPS patch file
            with open(self.ips_patch_path, "wb") as patchFile:
                for data in self.ips_patch_contents:
                    patchFile.write(data)
            patch = Patch.load(self.ips_patch_path)
            # Copy ifm.dll
            shutil.copy(self.ifm_prefix + self.ifm_suffix, self.ifm_prefix + self.ifm_temp + self.ifm_suffix)
            if not self.compareChecksum(self.ifm_prefix + self.ifm_temp + self.ifm_suffix):
                return
            shutil.copy(self.ifm_prefix + self.ifm_suffix, self.ifm_prefix + self.ifm_patched + self.ifm_suffix)
            # Apply patch to ifm_patched.dll
            with open(self.ifm_prefix + self.ifm_temp + self.ifm_suffix, "rb") as f_in:
                with open(self.ifm_prefix + self.ifm_patched + self.ifm_suffix, "wb") as f_out:
                    f_out.write(patch.apply(f_in.read()))
            # Delete temporary file
            os.remove(self.ifm_prefix + self.ifm_temp + self.ifm_suffix)
            # Delete IPS patch file
            os.remove(self.ips_patch_path)
        except Exception as e:
            ErrorMessageBox("An error occured while patching ifm.dll.", e)
            self.finish()
            return
        # This is a workaround to restart SFM
        try:
            timestamp = QtCore.QDateTime.currentDateTime().toString("yyyyMMdd_hhmmss")
            with open(self.restart_bat, "w") as restartFile:
                restartFile.write("""@echo off
    echo Backing up ifm.dll...
    move /Y "%s" "%s"
    echo Moving patched ifm.dll...
    move /Y "%s" "%s"
    echo Restarting SFM in 5 seconds...
    C:\\Windows\\System32\\timeout.exe /t 5
    start steam://rungameid/%s
    (goto) 2>nul & del \"%%~f0\"""" % (
                self.ifm_prefix + self.ifm_suffix,
                self.ifm_prefix + self.ifm_backup % timestamp + self.ifm_suffix,
                self.ifm_prefix + self.ifm_patched + self.ifm_suffix,
                self.ifm_prefix + self.ifm_suffix,
                self.sfm_app_id))
            # Tell the user that SFM will restart (no choice)
            ShowMessageBox("The patching process is complete. SFM will now restart to apply the changes.", Information)
            # Restart SFM
            os.system("start cmd /c %s" % self.restart_bat)
            sfm.console("quit")
            self.close()
        except Exception as e:
            ErrorMessageBox("An error occured while restarting SFM.", e)
            self.finish()

    sfm_app_id = "1840"
    restart_bat = "restart.bat"
    ifm_prefix = ".\\bin\\tools\\ifm"
    ifm_patched = "_patched"
    ifm_temp = "_temp"
    ifm_backup = "_backup_%s"
    ifm_suffix = ".dll"
    ifm_checksum = "d30b7ed67e2a72ccac7d096812dc126d"
    ips_patch_path = ".\\bin\\tools\\ifm_patch.ips"
    ips_patch_contents = [
        #   00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F   # Decoded text     # Offset (h) #
        b"\x50\x41\x54\x43\x48\x2C\xAD\x17\x00\x02\x00\x05\x2C\xAD\x27\x00", # PATCH,......,.'. # 0x00000000 #
        b"\x21\x89\x87\xE4\x01\x00\x00\xFF\xD3\x8B\x10\x68\xD0\x02\x00\x00", # !..a...yO'.hD... # 0x00000010 #
        b"\x89\xC1\x8B\x42\x1C\x68\xD8\x57\xA9\x10\xFF\xD0\x89\x87\xE8\x01", # .A'B.hOW..yD..e. # 0x00000020 #
        b"\x00\x00\x2C\xAD\x48\x00\x00\x00\x2D\x90\xA9\x3D\xD8\x00\x0F\x2D", # ..,.H...-..=O..- # 0x00000030 #
        b"\x73\x66\x6D\x5F\x68\x65\x69\x67\x68\x74\x00\x00\x00\x00\xAA\x7B", # sfm_height.....{ # 0x00000040 #
        b"\x08\x00\x13\x4B\x69\x77\x69\x66\x72\x75\x69\x74\x44\x65\x76\x20", # ...KiwifruitDev  # 0x00000050 #
        b"\x52\x50\x61\x74\x63\x68\xAE\x62\x2B\x01\x04\x57\x68\x69\x6C\x65", # RPatch.b+..While # 0x00000060 #
        b"\x20\x72\x65\x6E\x64\x65\x72\x69\x6E\x67\x20\x77\x69\x6C\x6C\x20", #  rendering will  # 0x00000070 #
        b"\x62\x65\x20\x75\x6E\x61\x66\x66\x65\x63\x74\x65\x64\x2C\x20\x74", # be unaffected, t # 0x00000080 #
        b"\x68\x65\x20\x76\x69\x65\x77\x70\x6F\x72\x74\x73\x20\x6D\x61\x79", # he viewports may # 0x00000090 #
        b"\x20\x62\x65\x0A\x75\x6E\x61\x62\x6C\x65\x20\x74\x6F\x20\x64\x69", # be.unable to di  # 0x000000A0 #
        b"\x73\x70\x6C\x61\x79\x20\x61\x6E\x20\x61\x63\x63\x75\x72\x61\x74", # splay an accurat # 0x000000B0 #
        b"\x65\x20\x70\x72\x65\x76\x69\x65\x77\x20\x6F\x66\x20\x79\x6F\x75", # e preview of you # 0x000000C0 #
        b"\x72\x20\x72\x65\x6E\x64\x65\x72\x2E\x0A\x54\x6F\x20\x66\x69\x78", # r render..To fix # 0x000000D0 #
        b"\x20\x74\x68\x69\x73\x20\x70\x72\x6F\x62\x6C\x65\x6D\x2C\x20\x69", #  this problem, i # 0x000000E0 #
        b"\x6E\x63\x72\x65\x61\x73\x65\x20\x74\x68\x65\x20\x67\x61\x6D\x65", # ncrease the game # 0x000000F0 #
        b"\x20\x77\x69\x6E\x64\x6F\x77\x20\x73\x69\x7A\x65\x0A\x77\x69\x74", # window size.wit  # 0x00000100 #
        b"\x68\x20\x2D\x77\x20\x61\x6E\x64\x20\x2D\x68\x20\x6F\x72\x20\x61", # h -w and -h or a # 0x00000110 #
        b"\x64\x6A\x75\x73\x74\x2F\x72\x65\x6D\x6F\x76\x65\x20\x74\x68\x65", # djust/remove the # 0x00000120 #
        b"\x20\x2D\x73\x66\x6D\x5F\x77\x69\x64\x74\x68\x20\x61\x6E\x64\x0A", # -sfm_width and.  # 0x00000130 #
        b"\x2D\x73\x66\x6D\x5F\x68\x65\x69\x67\x68\x74\x20\x70\x61\x72\x61", # -sfm_height para # 0x00000140 #
        b"\x6D\x65\x74\x65\x72\x73\x20\x66\x72\x6F\x6D\x20\x79\x6F\x75\x72", # meters from your # 0x00000150 #
        b"\x20\x63\x6F\x6D\x6D\x61\x6E\x64\x20\x6C\x69\x6E\x65\x2E\x0A\xAE", # command line...  # 0x00000160 #
        b"\x63\x2F\x00\x00\x00\x0E\x00\xAE\x76\x89\x00\x0A\x77\x69\x64\x74", # c/......v...widt # 0x00000170 #
        b"\x68\x00\x00\x00\x00\x00\xF5\x36\x26\x00\x02\x3C\x39\x45\x4F\x46", # h.....o6&..<9EOF # 0x00000180 #
    ]

NoIcon = QtGui.QMessageBox.NoIcon

Question = QtGui.QMessageBox.Question
Information = QtGui.QMessageBox.Information
Warning = QtGui.QMessageBox.Warning
Critical = QtGui.QMessageBox.Critical

def ShowMessageBox(message, icon=Information):
    msgBox = QtGui.QMessageBox()
    msgBox.setText(message)
    msgBox.setIcon(icon)
    title = ProductName
    if icon == Question:
        title = title + ": Question"
    elif icon == Warning:
        title = title + ": Warning"
    elif icon == Critical:
        title = title + ": Error"
    else:
        title = title + ": Information"
    msgBox.setWindowTitle(title)
    msgBox.exec_()

def ErrorMessageBox(message, exception):
    tb = traceback.extract_tb(sys.exc_info()[2])
    line = tb[-1][1]
    ShowMessageBox("%s\n\nError: %s (line %s)" % (message, exception, line), Critical)

try:
    # Create window if it doesn't exist
    PatchWindow().exec_()
except Exception  as e:
    import traceback
    traceback.print_exc()        
    ShowMessageBox("Error: %s" % e, Critical)
