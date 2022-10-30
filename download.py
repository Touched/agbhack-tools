import os
import datetime
import urllib.request
import platform
import sys
import ctypes
import tempfile
import subprocess
import shutil
import tarfile
import pe

def _parse(f, cls, offset, length=None):
    f.seek(offset)
    if length is None:
        buf = f.read(ctypes.sizeof(cls))
    else:
        buf = f.read(length) + b'\x00' * (ctypes.sizeof(cls) - length)
    return cls.from_buffer_copy(buf)


def extract7z(filename, output_directory):
    # There are no Python libraries that can satisfactorily cope with
    # 7z archives, so use the command line tool.
    os.makedirs(output_directory, exist_ok=True)
    p = subprocess.Popen([
        '7z',
        'x',
        filename,
        '-o' + os.path.abspath(output_directory),
        '-bd',
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    errors = p.communicate()[1]

    if p.wait():
        raise RuntimeError(errors.decode())


def extract_sfx(path, output_directory):
    """
    Extract a self-extracting (SFX) 7z archive to the specified directory.
    """

    with open(path, 'rb') as f:
        dos_header = _parse(f, pe.IMAGE_DOS_HEADER, 0)
        assert dos_header.e_magic == pe.IMAGE_DOS_SIGNATURE

        header = _parse(f, pe.IMAGE_NT_HEADERS, dos_header.e_lfanew)
        assert header.Signature == pe.IMAGE_NT_SIGNATURE

        offset = dos_header.e_lfanew + ctypes.sizeof(pe.IMAGE_NT_HEADERS)

        max_pointer = 0
        exe_size = 0
        for i in range(header.FileHeader.NumberOfSections):
            section_table = _parse(f, pe.IMAGE_SECTION_HEADER, offset)
            if section_table.PointerToRawData > max_pointer:
                max_pointer = section_table.PointerToRawData
                exe_size = section_table.PointerToRawData + section_table.SizeOfRawData
            offset += ctypes.sizeof(pe.IMAGE_SECTION_HEADER)

        f.seek(exe_size)
        archive_data = f.read()

        fd, filename = tempfile.mkstemp()
        os.write(fd, archive_data)
        os.close(fd)
        extract7z(filename, output_directory)
        os.remove(filename)


def get_devkitarm_download_url(suffix, revision='r46'):
    url = ('https://downloads.sourceforge.net/project/devkitpro/devkitARM/'
           'devkitARM_{revision}/devkitARM_{revision}-{suffix}')
    return url.format(suffix=suffix, revision=revision)


def main():
    os.makedirs('agbhack-tools/armips', exist_ok=True)

    if sys.platform == 'win32':
        url = get_devkitarm_download_url('win32.exe')
        filename = urllib.request.urlretrieve(url)[0]
        extract_sfx(filename, 'agbhack-tools/devkitarm')
        shutil.copytree('pokeruby-tools/tools', 'agbhack-tools/pokeruby')
        shutil.copyfile('armips/_Output/armips.exe', 'agbhack-tools/armips/armips.exe')
        output = 'agbhack-tools-win32.tar.xz'
    else:
        if sys.platform == 'darwin':
            url = get_devkitarm_download_url('x86_64-osx.tar.bz2')
        else:
            if platform.architecture()[0] == '64bit':
                url = get_devkitarm_download_url('x86_64-linux.tar.bz2')
            else:
                url = get_devkitarm_download_url('i686-linux.tar.bz2')

        filename = urllib.request.urlretrieve(url)[0]
        with tarfile.open(filename) as tarball:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tarball, "agbhack-tools/devkitarm")
        shutil.copytree('pokeruby/tools', 'agbhack-tools/pokeruby')
        shutil.copyfile('armips/armips', 'agbhack-tools/armips/armips')

        output = 'agbhack-tools-{platform}-{arch}.tar.xz'.format(
            platform=sys.platform,
            arch=platform.machine(),
        )

    with tarfile.open(output, 'w:xz', preset=9) as tarball:
        tarball.add('agbhack-tools')

    print('Created', output)


if __name__ == '__main__':
    main()
