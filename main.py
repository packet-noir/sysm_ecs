import argparse
import xml.etree.ElementTree as ET
import os.path
from pprint import pprint

# Accept Path to File
def take_file():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    args = parser.parse_args()
    return args.directory

# Ingest and Parse XML
def ingest_xml(arg):
    tree = ET.parse(arg)
    root = tree.getroot()
    return root

# Returns Dictionary Key/Value: 'Sysmon Field: Elastic Common Schema Field'
def sys_ecs_table():
    sys_ecs = {"Image": "process.executable",
                "CommandLine": "process.command_line",
                "User": "user.name",
                "ParentImage": "process.parent.executable"
                }
    return sys_ecs

# Map Fields 
def map_field(root, sys_ecs):
    ecs = {}
    for child in root[1]:
        if child.attrib.get('Name') in sys_ecs:
            ecs[sys_ecs.get(child.attrib.get('Name'))] = child.text
    path = ecs.get('process.executable').replace("\\", "/")
    ecs['process.name'] = os.path.basename(path)
    return ecs

def main():
    xml_file = take_file()
    data = ingest_xml(xml_file)
    sys_ecs = sys_ecs_table()
    pprint(map_field(data, sys_ecs))
main()
