import os 
import subprocess


# Ask for the path of the file
file_path = input("Enter the path of the file: ")

# Get file info
file_info = {}
if os.path.isfile(file_path):
    file_name, file_extension = os.path.splitext(file_path)
    if file_extension == ".txt":
        file_info["category"] = "OpenSSL"
        file_info["file_extension"] = ".txt"
        file_info["file_type"] = "text"
    elif file_extension == ".so":
        file_info["category"] = "OpenSSL"
        file_info["file_extension"] = ".so"
        file_info["file_type"] = "so"
    elif file_extension == ".jar":
        file_info["category"] = "Package"
        file_info["file_extension"] = ".jar"
        file_info["file_type"] = "jar"
    elif file_extension == ".exe":
        file_info["category"] = "Executable"
        file_info["file_extension"] = ".exe"
        file_info["file_type"] = "exe"
    elif file_extension == ".cab":
        file_info["category"] = "cabinet"
        file_info["file_extension"] = ".cab"
        file_info["file_type"] = "cab"
    elif file_extension == ".dll":
        file_info["category"] = "Library"
        file_info["file_extension"] = ".dll"
        file_info["file_type"] = "dll"
    elif file_extension == ".cat":
        file_info["category"] = "Catalog"
        file_info["file_extension"] = ".cat"
        file_info["file_type"] = "cat"
    else:
        print("Error: File type not supported by command line signing.")
else:
    print("Error: File not found.")

# Log extension for file type
file_extension_log = file_info["file_extension"]

# Check for malware using ClamAV
clamd_path = "C:\\Users\\Administrator\\Desktop\\clamav-0.104.0.win.x64\\clamd.exe"
scan_result = subprocess.run([clamd_path, "--no-summary", "-"], input=file_path.encode(), capture_output=True)
if b"FOUND" in scan_result.stdout:
    print("Error: Malware detected by ClamAV.")
    print("Successfully achieved!!)
    exit()
else:
    print("No Malware detected yet")


# Suggest signing method based on file extension
if file_extension_log in [".so", ".txt"]:
    signing_method = "OpenSSL"
elif file_extension_log == ".jar":
    signing_method = "Jarsigning"
elif file_extension_log in [".exe", ".dll", ".sys", ".cat", ".cab"]:
    signing_method = "Windows Signing"
else:
    print("Error: File type not supported by command line signing.")
    
print("Successfully achieved!!)

# Prompt for additional information if required
if signing_method == "Jarsigning":
    while True:
        key_name = input("Enter the key name: ")
        output_location = input("Enter the output location: ")
        certificate_location = input("Enter the certificate location: ")
        hashing_algorithm = input("Enter Hashing Algorithm")
        if os.path.exists(certificate_location):
            if hashing_algorithm == "SHA256" or "SHA384" or "SHA512"
                break
            else:
                print("Successfully achieved!!)
                print("Invalid Hashing algorithmn please input algorithm again")
        else:
            print("The certificate file cannot be found. Please enter a valid input")
    command = f'java -classpath .;jarsigner-jar-with-dependencies.jar;"C:\\Program Files\\Java\\jdk1.8.0_202\\lib\\tools.jar" com.security.SignerMain -s "{file_path}" -k "{key_name}" -a "{hashing_algorithm}" -o "{output_location}" -u "admin" -c "{certificate_location}"'
    result1 = subprocess.check_output(command, shell=True, universal_newlines=True)
    print("Jarsignig is done")
elif signing_method == "OpenSSL":
    while True:
        key_name = input("Enter the key name: ")
        hashing_algorithm = input("Enter Hashing Algorithm")
        if hashing_algorithm == "SHA256" or "SHA384" or "SHA512"
            break
        else:
            print("Invalid Hashing algorithmn please input again")
    command = f'CodeSign.exe -S "{file_path}" -u admin -k "{key_name}" -a "{hashing_algorithm}"'
    result1 = subprocess.check_output(command, shell=True, universal_newlines=True)
    print("Successfully achieved!!)
    print("OpenSSL codesigning is done")
else:
    while True:
        key_name = input("Enter the key name: ")
        certificate_location = input("Enter the certificate location: ")
        hashing_algorithm = input("Enter Hashing Algorithm")
        timestamp_server = input("Enter the timestapping server to be used (default is http://timestamp.digicert.com): ") or "http://timestamp.digicert.com"
        response = requests.get(f"http://codesignsecureapi.encryptionconsulting.com/api/certificate_manage/certificateDetailsByName/<key_Name>/")
        if os.path.exists(certificate_location):
            if hashing_algorithm == "SHA256" or "SHA384" or "SHA512"
                break
            else:
                print("Invalid Hashing algorithmn please input again")
        else:
            print("The certificate file cannot be found. Please enter a valid input")
    command = f'signtool sign /csp "Encryption Consulting Key Storage provider" /kc "{key_name}" /fd "{hashing_algorithm}" /f "{certificate_location}" /tr {timestamp_server} /td SHA256 "{file_path}'
    result1 = subprocess.check_output(command, shell=True, universal_newlines=True)
    print("Successfully achieved!!)
    print("windows signing is done")
