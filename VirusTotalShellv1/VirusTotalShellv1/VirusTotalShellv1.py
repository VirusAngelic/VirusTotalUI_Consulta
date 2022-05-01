# Author: Moises Diaz (git: VirusAngelic)
import os

import requests  # Requests en http
import csv  # For CSV writing
import json  # Handle json outputs
from datetime import datetime
import sys
from dotenv import load_dotenv

listAnalisis = list()
load_dotenv('.env')

def ipScan(apiKey):  # Function for a single ip query
    ip=input("Ingresa la ip a consultar")
    postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look, #making http request
                                 headers={
                                     "x-apikey": apiKey
                                     })
    return postIn.text


def ipScanFile(apiKey, path):
    # Scanning ips from file
    postInList=[]
    with open(path, "r") as f:
        lectura = f.readlines()
        for ind in lectura:
            if ind == "\r":
                lectura.remove("\r")
        for look in lectura:
           postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look,
                                 headers={
                                     "x-apikey": apiKey
                                     })
           postInList.append(postIn.json())
    return postInList
    
def exportaCSV(analisisJson):  # Making CSV from JSON format
    with open("Analisis.csv", "w") as writing:
        csv_writer = csv.writer(writing, delimiter=",")
        count = 0
        ROW_HEADERS = ["Ip", "Country", "ForcePoint", "Symantec", "Palo Alto Networks"]
        for keys in ROW_HEADERS:
            csv_writer.writerow(ROW_HEADERS)
        for keys in analisisJson:
            csv_writer.writerow(analisisJson[count]["data"]["id"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["country"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["last_analysis_results"]["Forcepoint ThreatSeeker"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["last_analysis_results"]["Forcepoint ThreatSeeker"])
            count += 1

def exportaTxt(analisisJson):  # Export as txt file
    with open("Analisis.txt", "w") as writing:
        writing.write(str(analisisJson))
        return analisisJson  # Return for shell operations

def main():
    try:

        APIKEY = os.getenv('VT_APIKEY')
        PATH = os.getenv('FILE_IPS_PATH')
        analisis = ipScanFile(APIKEY, PATH)  # Calling analisis function with apikey and path argues
        if analisis[0]['error']:
            print('Error en la solicitud a VirusTotal \n ====================  \n', analisis[0]['error']['message'])
            print('====================')
        else:
            exportaCSV(analisis)  # Making CSV file
            exportaTxt(analisis)  # Making txt file


    except :
        print("Ingresa una ruta de archivo valido")

if __name__== "__main__":
    main()