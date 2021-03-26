import vt
import requests
import jsonformatter
import csv
import json
from datetime import datetime
path = str
apiKey = str

def ipScan(apiKey):
    ip=input("Ingresa la ip a consultar")
    postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look,
                                 headers={
                                     "x-apikey": apiKey
                                     })
    return postIn.text

def parsingJson(string):
    parsed = json.dumps(string)
    return parsed

def ipScanFile(apiKey):
    global path
    postInList=[]
    path = input("Ingresa el path del archivo\n")
    with open(path,"r") as f:
        lectura=f.readlines()
        for look in lectura:
           postIn = requests.get("https://www.virustotal.com/api/v3/ip_addresses/"+look,
                                 headers={
                                     "x-apikey": apiKey
                                     })
           postInList.append(postIn.json())
    return postInList
    
"""def exportaCSV(analisis):

    timeNow=datetime.now()
    timestr=str(timeNow)
    csv_data = open("Analisis.csv","w")
    csv_writer = csv.writer(csv_data)
    analisis_data = analisis["data"]
    header = analisis_data.keys()
    csv_writer.writerow(header)
    csv_writer.writerow(analisis_data.values())
    csv_data.close()"""

def main():
    global apiKey
    apiKey=input("Ingresa la key\n")
    print(ipScanFile(apiKey))

if __name__== "__main__":
    main()