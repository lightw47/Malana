from api_keys_MA import vt_api_key
from write_console_output_MA import write_console_output
from write_csv_data_MA import write_csv_data
import argparse
import hashlib
import vt

vt_analysis_fields = ["filename", "sha256", "engine_name", "category", "result", "engine_update"]

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

def main():
    print("LightW's Malana - \"VT Scout\"")
    print()

    parser = argparse.ArgumentParser(description = "Shows last analysis results of given files. This script does NOT submit files to Virus Total, it just looks for their hashes in VT")
    parser.add_argument(
        "filename",
        type = str,
        nargs = '+',
        help = "Name of the file to be queried"
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
        
    data = vt_scout(fname_set)
    if args.o == None:
        print()
        write_console_output(data)
    else:
        write_csv_data(data, analysis_fields, args.o)
        print("Hashes of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()


