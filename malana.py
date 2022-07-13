from api_keys_MA import vt_api_key

import pefile
import hashlib
import ssdeep
import vt

hash_fields = ["filename", "hash_type", "section_name", "digest"]
pe_exp_fields = ["filename", "export"]
pe_imp_fields = ["filename", "dll_name", "import"]
vt_analysis_fields = ["filename", "sha256", "engine_name", "category", "result", "engine_update"]

hash_types = ["md5", "sha1", "sha256", "ssdeep", "imphash", "section_hash"]
HASH_MD5 = 0
HASH_SHA1 = 1
HASH_SHA256 = 2
HASH_SSDEEP = 3
HASH_IMPHASH = 4
HASH_SECTION = 5

def get_pe_exports(arg_fname_list):
    
    data = list()
    pe = 0

    for fname in arg_fname_list:
        
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                print("Processing exported symbols: " + fname)
                
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:

                    if exp.name != None:
                        data.append({
                            "filename": fname,
                            "export": exp.name.decode("utf-8")
                        })

                    else:
                        data.append({
                            "filename": fname,
                            "export": str(exp.ordinal)
                        })
            
            else:
                print("Have no export section: " + fname)
        
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return data


def get_pe_imports(arg_fname_list):
    
    data = list()
    pe = 0

    for fname in arg_fname_list:
        
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                print("Processing imported functions: " + fname)
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        
                        if imp.name != None:
                            data.append({
                                "filename": fname,
                                "dll_name": entry.dll.decode("utf-8"),
                                "import": imp.name.decode("utf-8")
                            })
                        
                        else:
                            data.append({
                                "filename": fname,
                                "dll_name": entry.dll.decode("utf-8"),
                                "import": str(imp.ordinal)
                            })
            
            else:
                print("Have no imported functions: " + fname)
        
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return data


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
            "filename": fname,
            "hash_type": hash_types[HASH_MD5],
            "section_name": None,
            "digest": digest
        })
        
        digest = hashlib.sha1(content).hexdigest()
        data.append({
            "filename": fname,
            "hash_type": hash_types[HASH_SHA1],
            "section_name": None,
            "digest": digest
        })
        
        digest = hashlib.sha256(content).hexdigest()
        data.append({
            "filename": fname,
            "hash_type": hash_types[HASH_SHA256],
            "section_name": None,
            "digest": digest
        })
    
        fuzzy_hash = ssdeep.hash_from_file(fname)
        data.append({
            "filename": fname,
            "hash_type": hash_types[HASH_SSDEEP],
            "section_name": None,
            "digest": fuzzy_hash
        })
    
        try:
            pe = pefile.PE(fname)
        
            imphash = pe.get_imphash()
            data.append({
                "filename": fname,
                "hash_type": hash_types[HASH_IMPHASH],
                "section_name": None,
                "digest": imphash
            })
            
            for section in pe.sections:
                sechash = section.get_hash_md5()
                data.append({
                    "filename": fname,
                    "hash_type": hash_types[HASH_SECTION],
                    "section_name": section.Name.decode("utf-8"),
                    "digest": sechash
                })
        
        except pefile.PEFormatError:
            "do nothing, this is not a PE file"
            
        f.close()

    return data


def vt_scout(arg_fname_list):

    data = list()

    with vt.Client(vt_api_key) as client:

        for fname in arg_fname_list:

            try:
                print("Scouting file: " + fname)
                with open(fname, "rb") as f:
                    content = f.read()
                    hash = hashlib.sha256(content).hexdigest()
                    vt_obj = client.get_object("/files/" + hash)
                    analysis = vt_obj.get("last_analysis_results")
                    
                    for entry in analysis:

                        data.append({
                            "filename": fname,
                            "sha256": hash,
                            "engine_name": analysis[entry]["engine_name"],
                            "category": analysis[entry]["category"],
                            "result": analysis[entry]["result"],
                            "engine_update": analysis[entry]["engine_update"]
                        })

            except vt.APIError as err:
                print("VirusTotal error: " + err.message)

            except FileNotFoundError:
                print("File not found: " + fname)

    return data


def search(arg_dataset, arg_criteria, arg_key):
    result = set()

    for entry in arg_dataset:

        match = True

        for c in arg_criteria:
            
            if entry[c] != arg_criteria[c]:
                match = False
                break

        if match:
            result.add(entry[arg_key])

    return result


def write_console_output(arg_dataset):
    
    for entry in arg_dataset:
        print(entry)


def write_csv_data(arg_dataset, arg_fields, arg_filename):
    with open(arg_filename, "w") as csv_file:
        
        # write fields header
        for i in range(0, len(arg_fields)):
            csv_file.write("\"" + arg_fields[i] + "\"")
            if i != len(arg_fields) - 1:
                csv_file.write(",")

        csv_file.write("\n")

        #write data
        for entry in arg_dataset:

            for i in range(0, len(entry)):
                if entry[arg_fields[i]] != None:
                    csv_file.write("\"" + entry[arg_fields[i]] + "\"")
                if i != len(entry) - 1:
                    csv_file.write(",")

            csv_file.write("\n")
