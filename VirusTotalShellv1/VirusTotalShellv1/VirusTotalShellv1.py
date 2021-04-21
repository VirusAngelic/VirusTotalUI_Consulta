# Autor: Moises Diaz (git: VirusAngelic)
import requests #Requests en http
import csv #For CSV writing
import json #Handle json outputs
from datetime import datetime
import sys

listAnalisis = list()  

def ipScan(apiKey): #Function for a single ip query
    ip=input("Ingresa la ip a consultar")
    postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look, #making http request
                                 headers={
                                     "x-apikey": apiKey
                                     })
    return postIn.text


def ipScanFile(apiKey,path): #Scanning ips from file
    postInList=[]
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
        ROW_HEADERS=["Ip","Country","ForcePoint","Symantec","Palo Alto Networks"]
        for keys in ROW_HEADERS:
            csv_writer.writerow(ROW_HEADERS)
        for keys in analisisJson:
            csv_writer.writerow(analisisJson[count]["data"]["id"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["country"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["last_analysis_results"]["Forcepoint ThreatSeeker"])
            csv_writer.writerow(analisisJson[count]["data"]["attributes"]["last_analysis_results"]["Forcepoint ThreatSeeker"])
            count+=1

def exportaTxt(analisisJson): #Export as txt file
    with open("Analisis.txt","w") as writing: 
        writing.write(str(analisisJson))
        return analisisJson #Return for shell operations

def main():
    try:
        #path=sys.argv[1] #Getting parameter from shel
        path="ipa.txt"
        apiKey = "e205541e1ef157f753580d9d866f9bb2d7bac8fbd8d6b5658fff387af5d818f3" #Using a default shell
        analisis=ipScanFile(apiKey,path) #Calling analisis function with apikey and path argues
        exportaCSV(analisis) #Making CSV file
        exportaTxt(analisis) #Making txt file
    except:
        print("Ingresa un path de archivo valido")

if __name__== "__main__":
    main()