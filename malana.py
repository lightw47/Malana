from api_keys import vt_api_key

import argparse
import hashlib
import time

import pefile
import ssdeep
import vt

hash_fields = ["filename", "hash_type", "section_name", "digest"]
pe_exp_fields = ["filename", "export"]
pe_imp_fields = ["filename", "dll_name", "import"]
vt_analysis_fields = ["filename", "sha256", "engine_name", "category", "result", "engine_update"]

def argparse_build_set(arg_description: str):
    
    parser = argparse.ArgumentParser(description = arg_description)
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
    
    return (set(args.filename), args.o)


def standalone_function(
    arg_dataset: set,
    arg_function,
    arg_fields: list,
    arg_output: str
):
           
    data = arg_function(arg_dataset) 
    if arg_output == None:
        print()
        write_console_output(data)
    else:
        write_csv_data(data, arg_fields, arg_output)
        print("Output written to " + arg_output)


def get_pe_exports(arg_fname_set: set) -> list:
    
    data = list()
    pe = 0

    for fname in arg_fname_set:
        
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


def get_pe_imports(arg_fname_set: set) -> list:
    
    data = list()
    pe = 0

    for fname in arg_fname_set:
        
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


def get_hashes(arg_fname_set: set) -> list:
    
    data = list()

    for fname in arg_fname_set:
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
            "hash_type": "md5",
            "section_name": None,
            "digest": digest
        })
        
        digest = hashlib.sha1(content).hexdigest()
        data.append({
            "filename": fname,
            "hash_type": "sha1",
            "section_name": None,
            "digest": digest
        })
        
        digest = hashlib.sha256(content).hexdigest()
        data.append({
            "filename": fname,
            "hash_type": "sha256",
            "section_name": None,
            "digest": digest
        })
    
        fuzzy_hash = ssdeep.hash_from_file(fname)
        data.append({
            "filename": fname,
            "hash_type": "ssdeep",
            "section_name": None,
            "digest": fuzzy_hash
        })
    
        try:
            pe = pefile.PE(fname)
        
            imphash = pe.get_imphash()
            data.append({
                "filename": fname,
                "hash_type": "imphash",
                "section_name": None,
                "digest": imphash
            })
            
            for section in pe.sections:
                sechash = section.get_hash_md5()
                data.append({
                    "filename": fname,
                    "hash_type": "section_hash",
                    "section_name": section.Name.decode("utf-8"),
                    "digest": sechash
                })
        
        except pefile.PEFormatError:
            "do nothing, this is not a PE file"
            
        f.close()

    return data


def vt_scout(arg_fname_set: set) -> list:

    data = list()

    with vt.Client(vt_api_key) as client:

        for fname in arg_fname_set:

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


def vt_submit(arg_fname_set: set) -> list:

    data = list()

    with vt.Client(vt_api_key) as client:

        for fname in arg_fname_set:

            try:
                
                f = open(fname, "rb")   
                analysis = client.scan_file(f, wait_for_completion=True)
                print(analysis.id)
                print("File submitted to VT: " + fname)
                
                f = open(fname, "rb")
                content = f.read()
                hash = hashlib.sha256(content).hexdigest()
                f.close()
                    
#                    for entry in analysis:
#
#                        data.append({
#                            "filename": fname,
#                            "sha256": hash,
#                            "engine_name": analysis[entry]["engine_name"],
#                            "category": analysis[entry]["category"],
#                            "result": analysis[entry]["result"],
#                            "engine_update": analysis[entry]["engine_update"]
#                        })

            except vt.APIError as err:
                print("VirusTotal error: " + err.message)

            except FileNotFoundError:
                print("File not found: " + fname)

    return data


def search(arg_dataset: list, arg_criteria: dict, arg_key: str) -> set:
    
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


def write_console_output(arg_dataset: list):
    
    for entry in arg_dataset:
        print(entry)


def write_csv_data(arg_dataset: list, arg_fields: list, arg_filename: str):
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
