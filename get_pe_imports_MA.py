import malana
import argparse

def main():
    print("LightW's Malana - \"Get PE Imports\"")
    print()

    parser = argparse.ArgumentParser(description = "List imported symbols of PE files")
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
        
    data = malana.get_pe_imports(fname_set)
    if args.o == None:
        print()
        malana.write_console_output(data)
    else:
        malana.write_csv_data(data, malana.pe_imp_fields, args.o)
        print("Imported symbols of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
