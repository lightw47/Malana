from write_console_output_MA import write_console_output
from write_csv_data_MA import write_csv_data
import argparse
import pefile
import hashlib
import ssdeep

hash_fields = ["File name", "Hash type", "Section name", "Digest"]
FIELD_FILENAME = 0
FIELD_HASHTYPE = 1
FIELD_SECNAME = 2
FIELD_DIGEST = 3

hash_types = ["md5", "sha1", "sha256", "ssdeep", "imphash", "section hash"]
HASH_MD5 = 0
HASH_SHA1 = 1
HASH_SHA256 = 2
HASH_SSDEEP = 3
HASH_IMPHASH = 4
HASH_SECTION = 5

def get_hashes(arg_fname_list):
    
    data = list()

    for fname in arg_fname_list:
        err = False
        
        try:
            f = open(fname, "rb")
        except FileNotFoundError:
            print("File not found: " + fname)
            err = True
            
        if err:
            continue
        
        print("Processing hashes of file: " + fname)
        content = f.read()
        
        digest = hashlib.md5(content).hexdigest()
        data.append({
            hash_fields[FIELD_FILENAME]: fname,
            hash_fields[FIELD_HASHTYPE]: hash_types[HASH_MD5],
            hash_fields[FIELD_SECNAME]: None,
            hash_fields[FIELD_DIGEST]: digest
        })
        
        digest = hashlib.sha1(content).hexdigest()
        data.append({
            hash_fields[FIELD_FILENAME]: fname,
            hash_fields[FIELD_HASHTYPE]: hash_types[HASH_SHA1],
            hash_fields[FIELD_SECNAME]: None,
            hash_fields[FIELD_DIGEST]: digest
        })
        
        digest = hashlib.sha256(content).hexdigest()
        data.append({
            hash_fields[FIELD_FILENAME]: fname,
            hash_fields[FIELD_HASHTYPE]: hash_types[HASH_SHA256],
            hash_fields[FIELD_SECNAME]: None,
            hash_fields[FIELD_DIGEST]: digest
        })
    
        fuzzy_hash = ssdeep.hash_from_file(fname)
        data.append({
            hash_fields[FIELD_FILENAME]: fname,
            hash_fields[FIELD_HASHTYPE]: hash_types[HASH_SSDEEP],
            hash_fields[FIELD_SECNAME]: None,
            hash_fields[FIELD_DIGEST]: fuzzy_hash
        })
    
        try:
            pe = pefile.PE(fname)
        
            imphash = pe.get_imphash()
            data.append({
                hash_fields[FIELD_FILENAME]: fname,
                hash_fields[FIELD_HASHTYPE]: hash_types[HASH_IMPHASH],
                hash_fields[FIELD_SECNAME]: None,
                hash_fields[FIELD_DIGEST]: imphash
            })
            
            for section in pe.sections:
                sechash = section.get_hash_md5()
                data.append({
                    hash_fields[FIELD_FILENAME]: fname,
                    hash_fields[FIELD_HASHTYPE]: hash_types[HASH_SECTION],
                    hash_fields[FIELD_SECNAME]: section.Name.decode("utf-8"),
                    hash_fields[FIELD_DIGEST]: sechash
                })
        
        except pefile.PEFormatError:
            "do nothing, this is not a PE file"
            
        f.close()

    return data

def main():
    print("LightW's Malana - \"Get Hashes\"")
    print()

    parser = argparse.ArgumentParser(description = "List hashes of files")
    parser.add_argument(
        "filename",
        type = str,
        nargs = '+',
        help = "Name of the file to be analyzed"
    )
    parser.add_argument(
        "-o",
        metavar = "csvoutput",
        type = str,
        required = False,
        help = "Output file where data is written in CSV format"
    )
    args = parser.parse_args()
    fname_set = set(args.filename)
        
    data = get_hashes(fname_set)
    if args.o == None:
        print()
        write_console_output(data)
    else:
        write_csv_data(data, hash_fields, args.o)
        print("Hashes of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
