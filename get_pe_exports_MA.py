import malana

print("LightW's Malana - \"Get PE Exports\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "List exported symbols of PE files"
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.get_pe_exports,
    arg_fields = malana.pe_exp_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
