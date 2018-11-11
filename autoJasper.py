from ares import CVESearch
from github import Github
from git import Repo
import linkGrabber
import os
import in_place
import shutil
import urllib.request

def findgitlink(url, identifier):
    links = linkGrabber.Links(url)
    print('url: '+url)
    gb = links.find()

    for item in gb:
        print(item['href'])
        if item['href'].startswith(identifier):
            return item['href']


def replace(file_path, pattern, subst):
    f = []

    for (dirpath, dirnames, filenames) in os.walk(file_path):
        f.extend(filenames)
        break
    for file in f:

        if file.endswith(".c") or file.endswith(".h"):
            with in_place.InPlace(file_path+"\\"+file) as my_file:
                for line in my_file:
                    line = line.replace(pattern, subst)
                    my_file.write(line)

'''
def replace(file_path , pattern1 , pattern2 , subst):
    f = []

    for (dirpath, dirnames, filenames) in os.walk(file_path):
        f.extend(filenames)
        break
    for file in f:

        if file.endswith(".c") or file.endswith(".h"):
            with in_place.InPlace(file_path+"\\"+file) as my_file:
                for line in my_file:
                    line = line.replace(pattern1, subst)
                    line = line.replace(pattern2,subst)
                    my_file.write(line)
'''
cve = CVESearch()
jasper_cve_id = []
git_link = ""
git_issue_link = ""
is_link_found = False
is_issue_link_found = False

data =  cve.search("jasper")['data']

for item in data:
    jasper_cve_id.append(item['id'])


print('Please write the cve that you wish to inspect')

cve_id_input = 'CVE-2016-8882'

for link in cve.id(cve_id_input)['references']:
    if link.startswith('https://github.com/mdadams/jasper/commit'):
        git_link = link
        is_link_found = True
    elif link.startswith('https://github.com/mdadams/jasper/issues'):
        git_issue_link = link
        is_issue_link_found = True
    if is_link_found and is_issue_link_found:
        break


if(not is_link_found):
    print('Link not found on cve, scraping the rest of the links')
    for link in cve.id(cve_id_input)['references']:
        git_link = findgitlink(link,'https://github.com/mdadams/jasper/commit')

        if not is_issue_link_found :
            git_issue_link = findgitlink(link,'https://github.com/mdadams/jasper/issues')

        if git_link != '' and git_link is not None and git_issue_link != '' and git_issue_link is not None:
            break

if(git_link is None):
    print('The git commit was not found on the cve, cant proceed')


else:
    print('Link found successfully')
    g = Github()
    repo = g.get_repo("mdadams/jasper")

    commit = repo.get_commit(sha=git_link.rsplit('/', 1)[-1])
    parent_sha = commit.commit.parents[0].sha
    print("sha : "+parent_sha)

directory = "C:\LabWork\\"+parent_sha

git_issue_download_link = ''

if git_issue_link is None or git_issue_link == '':
    print('The git issue link is not found, cant reproduce the exploit')

else:
    links = linkGrabber.Links(git_issue_link)
    gb = links.find()

    for item in gb:
        if item['href'].endswith('.zip'):
            git_issue_download_link = item['href']


if not os.path.exists(directory):
    os.makedirs(directory)

if len(os.listdir(directory) ) == 0:
    repo = Repo.clone_from(url="https://github.com/mdadams/jasper.git",to_path="C:\LabWork"+"\\"+parent_sha)
    print("Repository cloned")
    print("Checking out to the wanted commit")
    repo.git.checkout(parent_sha)
else:
    print("Repository is already cloned, proceeding")


if git_issue_download_link =='' or git_issue_download_link is None:
    print("can't find issue download link, cant proceed.")
else:
    download_path = "C:\\LabWork\\"+parent_sha+"\\reproducer.zip"
    with urllib.request.urlopen(git_issue_download_link) as response, open(download_path, 'wb') as out_file:
        data = response.read()  # a `bytes` object
        out_file.write(data)

filename1 = "C:\LabWork\\"+parent_sha+"\\src\libjasper\include\jasper"
filename2 = "C:\LabWork\\"+parent_sha+"\\src\libjasper\\base"
replace(filename1,"#include <jasper/jas_config.h>","#include <jasper/jas_config.h.in>")
replace(filename1,'#include "jasper/jas_config.h"','#include "jasper/jas_config.h.in"')
replace(filename2,"#include <jasper/jas_config.h>","#include <jasper/jas_config.h.in>")
replace(filename2,'#include "jasper/jas_config.h"','#include "jasper/jas_config.h.in"')
replace(filename2,'#include <math.h>','#include <jas_math.h>')

src = r"C:\LabWork\jasperInclude\include";
dst = "C:\\LabWork\\"+parent_sha+"\\src\\libjasper\\include\\jasper";

filename = "jas_math.h"
shutil.copy(os.path.join(src, filename), os.path.join(dst, filename))

path = directory+"\src\msvc\jasper.dsw"
command = "start /wait cmd /c Devenv "+ path +" /upgrade"
os.system(command)
path = directory+"\src\msvc\libjasper.dsp"
command = "start /wait cmd /c Devenv "+path+" /build Release"
os.system(command)



