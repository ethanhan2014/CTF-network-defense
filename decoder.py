import sys
import glob
import os
import subprocess
import base64
import re

default_output_file = "output.txt"
hex_pattern = r"^[\dabcdef]+:\s+.*"


def is_base64(data):
    try:
        return "==" in data and base64.b64encode(base64.b64decode(data)).decode("utf-8") == data.rstrip()
    except Exception:
        return False


def maybe_hex_dump(data):
    # there's probably a better way to check if file is a hexdump
    if re.match(hex_pattern, data):
        return True
    return False


def decode(filename, output_file):
    response = subprocess.run(["file", "--mime", filename], capture_output=True)
    if b"text/plain" in response.stdout:
        # lets first check if its base64 encoded or a possible hexdump
        base64_encoded = False
        hexdump = False
        with open(filename, "r") as file:
            # if the first line is base64 encoded, we can assume the entire file is ?
            first_line = file.readline()
            base64_encoded = is_base64(first_line)
            hexdump = maybe_hex_dump(first_line)
        if base64_encoded:
            decoded_file = f"{filename}_decoded"
            status, output = subprocess.getstatusoutput(f"base64 --decode {filename} > {decoded_file}")
            if int(status) == 0:
                return decode(decoded_file, output_file)
            print(f"Error while decoding: {output}\nmoving on..")
            return
        elif hexdump:
            r_hex_file = f"{filename}_r_hex"
            status, output = subprocess.getstatusoutput(f"xxd -r {filename} > {r_hex_file}")
            if os.path.exists(r_hex_file) and os.stat(r_hex_file).st_size != 0:
                return decode(r_hex_file, output_file)
            print(f"Error while reversing hexdump: {output}\nmoving on..")
            return
    if b"bzip" in response.stdout:
        proc = subprocess.run(["bzip2", "-d", filename], capture_output=True)
        if proc.returncode != 0:
            print(f"Error while bzip decompression: {proc.stderr}\nmoving on..")
            return
        decompressed = filename[:-4] if filename.endswith(".bz2") else filename  # remove extension after decompression
        return decode(decompressed, output_file)
    if b"gzip" in response.stdout:
        proc = subprocess.run(["bzip2", "-d", filename], capture_output=True)
        if proc.returncode != 0:
            print(f"Error while gzip decompression: {proc.stderr}\nmoving on..")
            return
        decompressed = filename[:-3] if filename.endswith(".gz") else filename  # remove extension after decompression
        return decode(decompressed, output_file)
    # if we've made it to this point the file is most likely a plain text
    try:
        with open(filename, "r") as file, open(output_file, "a") as output:
            # we only care about the first line, thats where flags are stored... i think
            first_line = file.readline()
            if first_line:
                output.write(first_line)
                return
    except Exception as e:
        print(f"Error while writing to output file: {e}")
        return


def hack(dir_path, output_file=default_output_file):
    for filename in glob.iglob(dir_path + '**/**', recursive=True):
        if os.path.isfile(filename):
            try:
                decode(filename, output_file)
            except Exception as err:
                # if we run into any issue we simply move on :)
                print(f"exception while decoding: {err}")
                pass


def clean_up(dir_path):
    result = subprocess.run(f"rm -r {dir_path}/*_decoded && rm -r {dir_path}/*r_hex", shell=True)
    if result.returncode == 0:
        print("clean up successful")
        return
    print(f"Error while cleaning up: {result.stderr}")


if __name__ == "__main__":
    # usage: python decoder.py path_to_root_directory
    root_dir = "."
    try:
        root_dir = os.path.realpath(sys.argv[1])
    except KeyError:
        pass
    hack(os.path.realpath(root_dir))
    clean_up(root_dir)
