import malana

print("LightW's Malana - \"Get Hashes\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "List hashes of files"
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.get_hashes,
    arg_fields = malana.hash_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
