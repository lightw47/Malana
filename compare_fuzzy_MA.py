import malana

print("LightW's Malana - \"Compare Fuzzy Hashes\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "Compare fuzzy hashes of all files"
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.compare_fuzzy,
    arg_fields = malana.comp_fuzzy_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
