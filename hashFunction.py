from argparse import ArgumentParser
from cryptography.hazmat.primitives import hashes


def hash(sorceFile_name: str, hashFunction_name: str) -> bytes:
    """Function that read a file and generate the Hash according chosen hash function

    Args:
        sorceFile_name (str): source file name to generate hash
        hashFunction_name (str): hash function to be used ("SHA-256",
         "SHA-384", "SHA-512", "MD5", "BLAKE-2")

    Returns:
        bytes: generated hash
    """
    # define hash funcition
    if hashFunction_name == "MD5":
        hashFunction = hashes.MD5()
    elif hashFunction_name == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hashFunction_name == "SHA-512":
        hashFunction = hashes.SHA512()
    elif hashFunction_name == "BLAKE-2":
        hashFunction = hashes.BLAKE2s(32)
    else:
        hashFunction = hashes.SHA256()
    # block length
    blockLength = 32
    # open sorce file
    sorceFile = open(sorceFile_name, 'r')
    # messa digest init
    digest = hashes.Hash(hashFunction)
    block = "."
    while block != "":
        # read block
        block = sorceFile.read(blockLength)
        # update digest
        digest.update(block.encode())
    # get hash
    h = digest.finalize()
    # close file
    sorceFile.close()

    return h
####################################################################################################


hashFunctions = ["SHA-256", "SHA-384", "SHA-512", "MD5", "BLAKE-2"]

if __name__ == "__main__":

    # argument parser
    parser = ArgumentParser()
    # optional arguments
    parser.add_argument('-hf',
                        '--hash-function',
                        action='store',
                        default='SHA-256',
                        help="define hash function, default=SHA-256, you can use {} as option".format(", ".join(hashFunctions)))
    # mandatory arguments
    parser_mandatory = parser.add_argument_group("mandatory arguments")
    parser_mandatory.add_argument('-sf',
                                  '--sorceFile',
                                  required=True,
                                  action='store',
                                  help="file from get the message")
    # getting arguments
    args = parser.parse_args()
    hashFunction_name = args.hash_function
    sorceFile_name = args.sorceFile
    # validate hash function
    if hashFunction_name not in hashFunctions:
        parser.exit(
            1, "hash function name ERROR\n\t'{}' is not a valid option, see the -h or --help for get help\n".format(hashFunction_name))

    h = hash(sorceFile_name, hashFunction_name)
    print(h)
