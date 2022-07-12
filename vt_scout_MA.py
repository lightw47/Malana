from api_keys_MA import vt_api_key
import hashlib
import sys
import vt

print("LightW's \"VT scout\"")
print()

argc = len(sys.argv)
if argc < 2:
    print("Please, provide at least one file name")
    exit()

client = vt.Client(vt_api_key)

for i in range(1, argc):
    try:
        print("Scouting file: " + sys.argv[i])
        content = open(sys.argv[i], "rb").read()
        sha256Hash = hashlib.sha256(content).hexdigest()
        vtObj = client.get_object("/files/" + sha256Hash)
        print("    SHA256 hash: " + sha256Hash)
        print("    File size: " + str(vtObj.size))
        for resultType in vtObj.last_analysis_stats:
            print("    " + str(resultType) + ": " + str(vtObj.last_analysis_stats[resultType]))
        print()
    except vt.APIError as err:
        print("VirusTotal reports an error:")
        print("    " + err.message)
        print()
    except FileNotFoundError:
        print("An error ocurred:")
        print("    File not found in disk: " + sys.argv[i])
        print()
        

client.close()
print("I'm leaving now, bye bye!")
