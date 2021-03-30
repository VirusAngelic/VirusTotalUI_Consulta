# Autor: Moises Diaz (git: VirusAngelic)
import requests #Requests en http
import csv #For CSV writing
import json #Handle json outputs
from datetime import datetime

listAnalisis = list()  

def ipScan(apiKey): #Function for a single ip query
    ip=input("Ingresa la ip a consultar")
    postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look, #making http request
                                 headers={
                                     "x-apikey": apiKey
                                     })
    return postIn.text


def ipScanFile(apiKey): #Scanning ips from file
    postInList=[]
    path = input("Ingresa el path del archivo\n")
    with open(path,"r") as f:
        lectura=f.readlines()
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
    
def exportaCSV(analisisJson): #Making CSV from JSON format
    with open("Analisis.csv","w") as writing:
        csv_writer = csv.writer(writing, delimiter = ",")
        count=0
        for keys in analisisJson:
            csv_writer.writerow(analisisJson[count]["data"])
            for attrib in (analisisJson[count]["data"]["attributes"].keys()):
                csv_writer.writerow(analisisJson[count]["data"]["attributes"].keys())
                csv_writer.writerow(analisisJson[count]["data"]["attributes"].values())
            count+=1

def exportaTxt(analisisJson): #Export as txt file
    with open("Analisis.txt","w") as writing: 
        writing.write(str(analisisJson))
        return analisisJson #Return for shell operations

def main():

    apiKey = input("Ingresa la key\n")
    analisis=ipScanFile(apiKey)
    exportaCSV(analisis)
    exportaTxt(analisis)

if __name__== "__main__":
    main()