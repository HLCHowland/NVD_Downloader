#Henry Howland
#2020 NVD Downloader
import glob
import pandas as pd
from io import BytesIO
from zipfile import ZipFile
import requests
import json
import datetime
import os
import platform



#Creates directories for NVD pulls according to OS type.
if "Windows" in platform.platform():
    dirDelim = "\\"
else:
    dirDelim = "/"
try:
    pathAllCVEs = (os.getcwd() + dirDelim +"AllCVEs"+ dirDelim)
    os.mkdir(pathAllCVEs)
except:
    pass
try:
    pathCVEsByYear = (os.getcwd() + dirDelim + "CVEsByYear" + dirDelim)
    os.mkdir(pathCVEsByYear)
except:
    pass



#Creates a list between now and when the NVD started tracking vulnerabilities.
thisYear = datetime.datetime.now().year
years = []
year = 2002
while year <= thisYear:
    years.append(year)
    year += 1



#Gets the vulnerabilities for each year then converts it into a CSV so that each year can be accessed individually.
for year in years:
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % str(year)
    response = requests.get(url)
    data = {}
    zipfile = ZipFile(BytesIO(response.content))
    data = json.loads(zipfile.read('nvdcve-1.1-'+str(year)+'.json'))
    CVEs = pd.json_normalize(data['CVE_Items'])
    CVEs.to_csv(pathCVEsByYear + 'nvdcve-1.1-'+str(year)+'.csv')



#Gets every year of vulnerabilities and combines them into one file.
os.chdir(pathCVEsByYear)
all_filenames = [i for i in glob.glob('*.{}'.format("csv"))]
combined_csv = pd.concat([pd.read_csv(f, low_memory=False) for f in all_filenames ])
combined_csv.to_csv(pathAllCVEs + "combinedNVD.csv", index=False, encoding='utf-8-sig')
