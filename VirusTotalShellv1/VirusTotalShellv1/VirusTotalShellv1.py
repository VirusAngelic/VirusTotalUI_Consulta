import vt
path = str
apiKey = str
#client = vt.Client(apikey)
def upload():
    global path
    global apiKey
    apiKey=input("Ingresa la key\n")
    client = vt.Client(apiKey)
    path = input("Ingresa el path del archivo\n")
    with open(path,"rb") as f:
        analisis = client.scan_file(f, wait_for_completion=True)
    return analisis
    
def about():
    apiKey = input("entra")
    client=vt.Client(apiKey)
    file = client.get_object("/files/"+"NDhkMGJkOTJmY2I2ZTlhZDJmMGY3NmI1NmQ4YmNiZTU6MTYxNjY1MjU2Ng")
    print(file.last_analysis_stats)

def main():
    """global path
    cliente=upload()
    print(cliente)
    print("Obtener informacion de un archivo?\n")"""
    about()


if __name__== "__main__":
    main()