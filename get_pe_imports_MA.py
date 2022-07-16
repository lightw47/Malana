import malana

print("LightW's Malana - \"Get PE Imports\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "List imported symbols of PE files"
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.get_pe_imports,
    arg_fields = malana.pe_imp_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
