import eel, os, wx, pytsk3, pyshark, csv, json, sys,  pathlib, sqlite3, re
from io import StringIO

eel.init('web')

paths = []
numFiles = 0
ram_paths = []
disk_paths = []
pcap_paths = []
    
@eel.expose
def getPath(wildcard="*"):
    global numFiles
    global paths
    app = wx.App(None)
    style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
    dialog = wx.FileDialog(None, 'Open', wildcard=wildcard, style=style)
    if dialog.ShowModal() == wx.ID_OK:
        paths.append(dialog.GetPath()) # add path to list of file paths
        numFiles += 1 # increment number of files provided
        dialog.Destroy()
        return paths
    else:
        dialog.Destroy()
        return paths

@eel.expose
def extractArtifacts():
    global ram_paths
    global disk_paths
    global pcap_paths
    global paths

    if paths:
        for path in paths:
            filename, file_extension = os.path.splitext(path)
            if file_extension == '.txt' or file_extension == '.dmp' or file_extension == '.dump':
                ram_paths.append(filename+file_extension)
            if file_extension == '.img' or file_extension == '.iso' or file_extension == '.vmdk' or file_extension == '.raw':
                disk_paths.append(filename+file_extension)
            if file_extension == '.pcap' or file_extension == '.pcapng':
                pcap_paths.append(filename+file_extension)
            else:
                continue

    print("MEMORY DUMPS\n")
    print("\n".join(ram_paths) + "\n")
    print("DISK IMAGES\n")
    print("\n".join(disk_paths) + "\n")
    print("PCAP FILES\n")
    print("\n".join(pcap_paths) + "\n")


    csvs = []
    artifacts = []
    if pcap_paths:
        csvs = analyzePCAP(pcap_paths)
        artifacts.append(csvs[0][6:])

    # artifacts.append("hello")

    if ram_paths:
        memData = analyzeRAM(ram_paths)
        artifacts.append(memData)


    if disk_paths:
        # ignition_dir = carveDisk(disk_paths)
        # analyzeDisk(ignition_dir)
        diskTags = analyzeDisk("./web/data/Ignition_Disk_Files")
        artifacts.append(diskTags[6:])

    paths.clear()

    return artifacts


def carveDisk(disk_paths):

    for disk_path in disk_paths:

        # Define a directory to save carved files
        output_dir = './web/data/Ignition_Disk_Files'

        # Define the target directory to carve (absolute path in the file system)
        target_directory = 'Program Files/Inductive Automation/Ignition'  # Adjust this to your specific directory path within the image

        # Create the output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Open the raw disk image using pytsk3
        img = pytsk3.Img_Info(disk_path)

        # # Testing
        # partition_table = pytsk3.Volume_Info(img)
        # for partition in partition_table:
        #     print(f"Partition: {partition.addr}, Start: {partition.start}, Length: {partition.len}, Description: {partition.desc.decode().strip()}")

        # Open the file system on the disk image 
        partition_table = pytsk3.Volume_Info(img)
        selected_partition = None

        for partition in partition_table:
            if partition.desc.decode() == "Basic data partition":  # Adjust the partition number accordingly
                selected_partition = partition
                break

        if selected_partition is not None:
            # Calculate the byte offset to the start of the selected partition
            partition_offset = selected_partition.start * 512  # Assuming 512 bytes per sector

            # Open the file system at the partition's start point
            file_system = pytsk3.FS_Info(img, offset=partition_offset)
            
            print("File system opened for partition", selected_partition.addr)
        else:
            print("Partition not found.")
            return

        # Function to find the directory entry for a given path
        def find_directory_entry(fs, directory_path):
            directory_path_parts = directory_path.split("/")
            current_directory = fs.open_dir('/')
            
            for part in directory_path_parts:
                print("PART: ", part, "\n")
                found = False
                for file_entry in current_directory:
                    print("FILE: ", file_entry.info.name.name.decode('utf-8', errors='replace'), "\n")
                    if file_entry.info.name.name.decode('utf-8', errors='replace') == part:
                        if file_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            current_directory = file_entry.as_directory()
                            found = True
                            break
                if not found:
                    raise FileNotFoundError(f"Directory '{directory_path}' not found in the image.")
            
            return current_directory

        # Carve files from the Ignition directory
        def carve_files_from_directory(directory, fs, dir_path=''):
            for file_entry in directory:
                # Ignore '.' and '..' directories
                if file_entry.info.name.name in [b'.', b'..']:
                    continue

                file_path = os.path.join(dir_path, file_entry.info.name.name.decode('utf-8', errors='replace'))
                
                # If the entry is a directory, recurse into it
                if file_entry.info.meta and file_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    print(f"Entering directory: {file_path}")
                    carve_files_from_directory(file_entry.as_directory(), fs, file_path)
                
                # If the entry is a file, attempt to carve it
                elif file_entry.info.meta and file_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    print(f"Carving file: {file_path}")
                    save_carved_file(file_entry, file_path)

        # Save files
        def save_carved_file(file_entry, file_path):
            try:
                file_size = file_entry.info.meta.size
                if file_size > 0:
                    output_file_path = os.path.join(output_dir, file_path.strip(os.sep))

                    # Create the necessary subdirectories if they don't exist
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                    with open(output_file_path, 'wb') as f:
                        file_object = file_entry.read_random(0, file_size)
                        f.write(file_object)

                    print(f"File carved: {output_file_path} (Size: {file_size} bytes)")
                else:
                    print(f"Skipping empty file: {file_path}")
            except Exception as e:
                print(f"Failed to carve file: {file_path}, Error: {e}")

        # Start carving files from the specific target directory
        try:
            directory_entry = find_directory_entry(file_system, target_directory)
            carve_files_from_directory(directory_entry, file_system, target_directory)
        except Exception as e:
            print(f"Error: {e}")

    return output_dir

def analyzeDisk(path):
    dir_path = str(pathlib.Path().resolve()) + "\\" + path + "\Program Files\Inductive Automation\Ignition"
    csv_output_file = ".\web\data\ignition_disk_file_info.csv"
    analysis_files = []
    diskTags = []

    csv_fields = [
                    'Name',
                    'Size',
                    'Path'
        ]

    with open(csv_output_file, mode='w', newline='') as f:
            csv_writer = csv.DictWriter(f, fieldnames=csv_fields)
            csv_writer.writeheader()

            for path, dirs, files in os.walk(dir_path):
                for dirname in dirs:
                    file_info = {
                            'Name': dirname,
                            'Path': os.path.join(path, dirname),
                            'Size': os.path.getsize(os.path.join(path, dirname))
                        }
                    
                for filename in files:
                    file_info = {
                            'Name': filename,
                            'Path': os.path.join(path, filename),
                            'Size': os.path.getsize(os.path.join(path, filename))
                        }
                    
                    if "config.idb" in filename:
                        analysis_files.append(os.path.join(path, filename))

                    csv_writer.writerow(file_info)


    dbfile = analysis_files[0]
    # Create a SQL connection to our SQLite database
    conn = sqlite3.connect(dbfile)

    # creating cursor
    cur = conn.cursor()

    table_list = [a[0] for a in cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]

    print(f"DATABSE TABLES RECOVERED: {table_list}")

    field_names = [
        'ID',
        'PROVIDERID',
        'FOLDERID',
        'CFG',
        'RANK',
        'NAME'
    ]
    
    csv_output_file = ".\web\data\\tagconfig.csv"
    with open(csv_output_file, mode='w', newline='') as f:
            csv_writer = csv.DictWriter(f, fieldnames=field_names)
            csv_writer.writeheader()

            for row in cur.execute("SELECT * FROM " + 'TAGCONFIG'):
                info = {
                    'ID': row[0],
                    'PROVIDERID': row[1],
                    'FOLDERID': row[2],
                    'CFG': row[3],
                    'RANK': row[4],
                    'NAME': row[5]
                }

                tagData = json.loads(row[3])
                if tagData['tagType'] == 'AtomicTag':
                    tagName = "(" + str(row[0]) + ") " + str(row[5])
                    tag_dict = {
                        'name': tagName,
                        'data': tagData
                    }
                    diskTags.append(tag_dict)

                csv_writer.writerow(info)

    field_names = [
        'DEVICESETTINGS ID',
        'NAME',
        'TYPE',
        'DESCRIPTION',
        'ENABLED'
    ]

    csv_output_file = ".\web\data\\devicesettings.csv"
    with open(csv_output_file, mode='w', newline='') as f:
            csv_writer = csv.DictWriter(f,fieldnames=field_names)
            csv_writer.writeheader()

            for row in cur.execute("SELECT * FROM " + 'DEVICESETTINGS'):
                info = {
                    'DEVICESETTINGS ID': row[0],
                    'NAME': row[1],
                    'TYPE': row[2],
                    'DESCRIPTION': row[3],
                    'ENABLED': row[4]
                }
                csv_writer.writerow(info)

    print(diskTags)
    print(f"NUM DISK TAGS: {len(diskTags)}")

    tagJson = json.dumps(diskTags)
    json_output_file = ".\web\data\\tagDiskData.json"
    with open(json_output_file, "w") as outfile:
        outfile.write(tagJson)

    conn.close()

    return json_output_file


# Function to extract valid JSON objects from text
def extract_json_from_text(text_file):
    json_objects = []  # List to hold valid JSON objects
    buffer = ""  # Buffer to accumulate potential JSON content
    in_json = False  # Flag to track if we're inside a JSON object
    open_braces = 0  # Track nested braces

    # Read the file line by line
    with open(text_file, 'r') as f:
        for line in f:
            for char in line:
                if char == '{':
                    if not in_json:
                        in_json = True  # Start of JSON object
                    open_braces += 1  # Increment open brace count
                if in_json:
                    buffer += char  # Accumulate characters into buffer
                if char == '}':
                    open_braces -= 1  # Decrement brace count
                    if open_braces == 0:
                        # End of JSON object
                        in_json = False
                        try:
                            # Try to load and validate JSON
                            json_obj = json.loads(buffer)
                            json_objects.append(json_obj)  # Append valid JSON object
                        except json.JSONDecodeError:
                            # If JSON is not valid, skip it
                            pass
                        buffer = ""  # Reset buffer for the next JSON object

    return json_objects

# Function to write extracted JSON objects to a file
def write_json_to_file(infile):

    # Path to the output JSON file
    outfile = "./web/data/" + infile.split("\\")[-1] + '_json_outfile.json'

    # Extract JSON objects from the text file
    json_objects = extract_json_from_text(infile)

    # Write the valid JSON objects to a new file
    with open(outfile, 'w') as f:
        for obj in json_objects:
            json.dump(obj, f)
            f.write('\n')  # Separate each JSON object by a newline
    
    print(f"Extracted {len(json_objects)} JSON objects.")

def parseTagData(infile):
    tagNum = 0
    deviceNum = 0
    tagPaths = {}
    devices = {}

    with open(infile, 'r', encoding='utf-8', errors="ignore") as f:
        print("file opened")
        for line in f:
            line = line.strip()
            # print(line)
            tagData = re.search(r'"tagPath":\s".+\.value', line)
            deviceData = re.search(r'Devices\/(.*?)(\/Enabled)', line)
        
            if tagData is not None:
                print(tagData)
                tagNum += 1
                tagPaths[tagData.group(0)] = tagNum
            
            if deviceData is not None:
                if "\x00" not in deviceData.group(0): # Ignore potentially corrupted data
                    print(deviceData)
                    deviceData = deviceData.group(0).replace("Devices/", "")
                    deviceData = deviceData.replace("/Enabled", "")
                    deviceNum += 1
                    devices[deviceData] = deviceNum

    print(tagPaths)
    print(devices)
    print(f"HITS: {tagNum}")
    print(f'TOTAL: {len(tagPaths)}')
    finalTagData = []
    finalDeviceData = []

    for tag in tagPaths.keys():
        tagDict = {
            'path': tag
        }
        finalTagData.append(tagDict)

    for device in devices.keys():
        deviceDict = {
            'name': device
        }
        finalDeviceData.append(deviceDict)
        

    tagJson = json.dumps(finalTagData)
    deviceJson = json.dumps(finalDeviceData)
    tag_json = ".\web\data\\tagMemData.json"
    device_json = ".\web\data\\deviceMemData.json"
    with open(tag_json, "w") as outfile:
        outfile.write(tagJson)
    with open(device_json, "w") as outfile:
        outfile.write(deviceJson)

    return (tag_json[6:], device_json[6:])


# Convert binary file to readable ASCII/UTF-8 text
def binary_to_text(infile, encoding='utf-8'):

    outfile = "./web/data/" + infile.split("\\")[-1] + '_text.txt'
    if os.path.exists(outfile): 
        os.remove(outfile) 

    with open(infile, 'rb') as f:
        with open(outfile, 'w') as f2:
            data = True
            while data:
                data = f.read(1)  # Read binary data
                try:
                    text_data = data.decode(encoding)  # Try to decode to text (e.g., UTF-8)
                    if text_data == '\x00':
                        text_data = ' '
                    f2.write(text_data)
                except UnicodeDecodeError:
                    # print(f"Error: Unable to decode binary file as {encoding}.")
                    continue

    return outfile


def analyzeRAM(ram_paths):

    for path in ram_paths:
        # filename, file_extension = os.path.splitext(path)
        # if file_extension != ".txt":
        #     new_path = binary_to_text(path)
        #     print(new_path)
        #     write_json_to_file(new_path)
        # else:
        print("beginning")
        paths = parseTagData(path)
        # write_json_to_file(path)

    return paths

global csv_paths
global pcap_data

def getMdbsFuncCode(data):
    if int(data) == 1:
        func_code = "Read Coils"
    elif int(data) == 2:
        func_code = "Read Discrete Inputs"
    elif int(data) == 3:
        func_code = "Read Holding Registers"
    return func_code

def analyzePCAP(pcap_paths):
    global pcap_data
    pcap_data = {}
    requests = 0
    responses = 0
    
    for pcap_file in pcap_paths:

        # Define a Packet Filter for ModbusTCCP and SIEMENS S7 COMM packets
        packet_filter = 'modbus || s7comm'  # Adjust as needed

        # Path to the output CSV file
        csv_output_file = "./web/data/" + pcap_file.split('\\')[-1] + '_filtered.csv'

        # Define the fields to extract and save in the CSV
        csv_fields = [
                        'No.',
                        'Length',
                        'Source',
                        'Destination',
                        'TCP Src Port',
                        'TCP Dest Port',
                        'TCP Stream',
                        'Modbus Function Code',
                        'S7 Comm Parameter',
                        'Data',
                        'Timestamp'
                    ]

        # Open the PCAP file with the specified filter using pyshark
        packets = pyshark.FileCapture(pcap_file, display_filter=packet_filter, output_file= "./web/data/" + pcap_file.split('\\')[-1] + "_filtered.pcap", keep_packets=False)
        # packets.load_packets()

        # Open a CSV file to write the filtered packet data
        with open(csv_output_file, mode='w', newline='') as f:
            csv_writer = csv.DictWriter(f, fieldnames=csv_fields)
            
            # Write header to the CSV
            csv_writer.writeheader()

            # Iterate over each packet in the filtered capture
            for i, packet in enumerate(packets):
                # try:
                    # Extract relevant packet data (modify as needed)

                    isModbus = False

                    if "MODBUS" in str(packet.layers[-1]):
                        func_code = packet.layers[-1]._all_fields["modbus.func_code"]
                        isModbus = True
                    elif "S7COMM" in str(packet.layers[-1]):
                        func_code = "N/A"
                    else:
                        print(str(packet.layers[-1]))

                    if isModbus:
                        old_stdout = sys.stdout
                        buff = StringIO()
                        sys.stdout = buff
                        packet.modbus.pretty_print()
                        sys.stdout = old_stdout
                        data = buff.getvalue()
                    else:
                        old_stdout = sys.stdout
                        buff = StringIO()
                        sys.stdout = buff
                        data = packet.s7comm.pretty_print()
                        sys.stdout = old_stdout
                        data = buff.getvalue()

                    if packet.ip._all_fields["ip.src"] not in pcap_data.keys():
                        if isModbus:
                            if len(packet.modbus._all_fields) > 3:
                                pcap_data[packet.ip._all_fields["ip.src"]] = "PLC"
                            else:
                                pcap_data[packet.ip._all_fields["ip.src"]] = "HOST"
                        else:
                            if "Ack" in packet.s7comm.header:
                                pcap_data[packet.ip._all_fields["ip.src"]] = "PLC"
                            else:
                                pcap_data[packet.ip._all_fields["ip.src"]] = "HOST"

                    packet_info = {
                        'No.': i + 1,  # Packet number
                        'Length': packet.length,
                        'Source': packet.ip._all_fields["ip.src"] + " (" + pcap_data[packet.ip._all_fields["ip.src"]] + ")",
                        'Destination': packet.ip._all_fields["ip.dst"],
                        'TCP Src Port': packet.tcp._all_fields["tcp.srcport"],
                        'TCP Dest Port': packet.tcp._all_fields["tcp.dstport"],
                        'TCP Stream': packet.tcp._all_fields["tcp.stream"],
                        'Modbus Function Code': func_code + ": " + getMdbsFuncCode(func_code) if isModbus else "N/A",
                        'S7 Comm Parameter': packet.layers[-1]._all_fields["s7comm.param"] if not isModbus else "N/A",
                        'Data': data,
                        'Timestamp': packet.sniff_timestamp
                    }

                    if "HOST" in packet_info['Source']:
                        requests += 1
                    elif "PLC" in packet_info['Source']:
                        responses += 1

                    # Write the packet information to the CSV file
                    csv_writer.writerow(packet_info)

                # except AttributeError:
                #     # In case a packet does not have the expected attributes, skip it
                #     continue

        # Close the packet capture
        packets.close()

        print(f"Filtered packets saved to {csv_output_file}")

        print(f'REQUESTS: {requests} \n RESPONSES: {responses}')

        global csv_paths
        csv_paths = []
        csv_paths.append(csv_output_file)

    return csv_paths

if __name__=="__main__":
    eel.start("index.html")