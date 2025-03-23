import os
import tempfile


def create_name_from_address(name):

    # Process the name, converting integers to 'MEM_0xXXXX' format
    if isinstance(name, int):
        return "MEM_" + hex(name)

    return name


def backup_file(filepath):

    bak = f"{filepath}.bak"

    if os.path.exists(filepath):

        if os.path.exists(bak):
            os.remove(bak)

        os.rename(filepath, bak)


def get_temp_dir(root_filename):

    # Create a temporary directory to store the snapshot
    temp_dir = tempfile.gettempdir()

    # get current binary name
    file_name = os.path.splitext(root_filename)[0]
    temp_dir = os.path.join(temp_dir, file_name)

    # create it
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)

    return temp_dir


def tohex(val, PTR_SIZE):

    nbits = PTR_SIZE * 8
    return hex((val + (1 << nbits)) % (1 << nbits))
