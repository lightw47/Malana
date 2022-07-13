import malana
import argparse

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
        
    data = malana.vt_scout(fname_set)
    if args.o == None:
        print()
        malana.write_console_output(data)
    else:
        malana.write_csv_data(data, malana.analysis_fields, args.o)
        print("Hashes of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()


