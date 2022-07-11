import sys
import pefile
import hashlib
import ssdeep
import csv

hash_fields = ["File name", "Hash type", "Digest"]
hash_types = ["md5", "sha1", "sha256", "ssdeep", "imphash", "section "]
HASH_MD5 = 0
HASH_SHA1 = 1
HASH_SHA256 = 2
HASH_SSDEEP = 3
HASH_IMPHASH = 4
HASH_SECTION = 5

def generate_hash_list(arg_fname_list):
    list_dict = list()

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
        list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_MD5], hash_fields[2]: digest})
        
        digest = hashlib.sha1(content).hexdigest()
        list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_SHA1], hash_fields[2]: digest})
        
        digest = hashlib.sha256(content).hexdigest()
        list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_SHA256], hash_fields[2]: digest})
    
        fuzzy_hash = ssdeep.hash_from_file(fname)
        list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_SSDEEP], hash_fields[2]: fuzzy_hash})
    
        try:
            pe = pefile.PE(fname)
        
            imphash = pe.get_imphash()
            list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_IMPHASH], hash_fields[2]: imphash})
            
            for section in pe.sections:
                sechash = section.get_hash_md5()
                list_dict.append({hash_fields[0]: fname, hash_fields[1]: hash_types[HASH_SECTION] + section.Name.decode("utf-8"), hash_fields[2]: sechash})
        except pefile.PEFormatError:
            'nothing'
            
        f.close()
    return list_dict

def main():
    print("LightW's \"Get Hashes\"")
    print()

    argc = len(sys.argv)

    if argc == 1:
        print("Usage:")
        print("lw_get_hashes.py <outfile (csv)> <filename> [filename] [filename] ...")
        exit()

    if argc == 2:
        print("Please, provide at least one file")
        exit()
        
    fname_list = list()
    for i in range(2, argc):
        fname_list.append(sys.argv[i])
        
    with open(sys.argv[1], "w") as outfile:    
        list_dict = generate_hash_list(fname_list)
        csvw = csv.DictWriter(outfile, fieldnames = hash_fields, escapechar = ';')
        csvw.writeheader()
        csvw.writerows(list_dict)
        
        print("Hashes of files provided written to " + sys.argv[1])

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
