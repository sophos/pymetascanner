# Metadefender scan a folder.
# A folder is passed in as the parameter.
# pymetascanner.py /path/to/some/folder

import sys, os, hashlib, urllib2, json

#
serverurl = 'https://mymetadefenderserver.local:443'
watchlist = []
failedlist = []

class EnhancedFile(file):
	def __init__(self, name):
		file.__init__(self, name, "rb")
	def __len__(self):
		return os.fstat(self.fileno()).st_size


class scannedfileentry():
    filename = ''
    checksum = ''

    def __init__(self, name, checksum):
        self.filename = name
        self.checksum = checksum

    def __eq__(self, other):
        return ((self.filename == other.filename) and (self.checksum == other.checksum))


def addtowatched(entry):
    if(entry in watchlist == False):
        watchlist.append(entry)

def addtofailed(entry):
    if(entry in failedlist == False):
        failedlist.append(entry)


def checksumfile(thepath):
    hasher = hashlib.sha256()
    with open(thepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Chunked from Server
def getprogresspercentage(data):
    if(data.has_key('process_info') == True):
        inner = data['process_info']
        if(inner.has_key('progress_percentage') == True):
            return inner['progress_percentage']
    return 0

# Is the scan successful
def isscansuccessful(data):
    if(data.has_key('process_info') == True):
        inner = data['process_info']
        if(inner.has_key('result') == True):
            return inner['result'] == 'Allowed'
    return False

#
def doscanfile(thepath, cs):
    fname = os.path.split(thepath)[1]
    headers = {'Content-Type': 'application/octet-stream', 'filename':fname}
    fp = EnhancedFile(thepath)
    req = '{0}/{1}'.format(serverurl, 'file')
    request = urllib2.Request(req, fp, headers)
    data = json.load(urllib2.urlopen(request))
    print 'file scanned'
    # check the result.
    req = '{0}/{1}/{2}'.format(serverurl, 'file', data['data_id'])
    data = json.load(urllib2.urlopen(req))
    if(getprogresspercentage(data) < 100):
        addtowatched(scannedfileentry(thepath, cs))
        return

    if(isscansuccessful(data) == False):
        print 'Scan failed.'
        addtofailed(scannedfileentry(thepath, cs))


def getfilestatusdata(thepath, cs):
    req = '{0}/{1}/{2}'.format(serverurl, 'hash', cs)
    urllib2.getproxies = lambda: {}
    return json.load(urllib2.urlopen(req))


def managescanfile(thepath):
    print 'Scanning [%s]' % thepath
    cs = checksumfile(thepath)
    data = getfilestatusdata(thepath, cs)

    if(data.has_key(cs) == True):
        print 'File has not been cached, will scan it.'
        doscanfile(thepath, cs)
    else:
        print 'File has already been scanned.'
        # check the scan result.
        if(getprogresspercentage(data) < 100):
            print 'The file is being scanned by another process.'
            addtowatched(scannedfileentry(thepath, cs))
        else:
            if(isscansuccessful(data)):
                print 'The file was scanned and is good to go.'
            else:
                print 'The file was scanned and found to be bad.'
                addtofailed(scannedfileentry(thepath, cs))



def processpath(thepath):
    if(os.path.isdir(thepath) == False):
        if(os.path.exists(thepath) == False):
            print 'The path [%s] does not exist.' % thepath
            sys.exit(1)
        else:
            managescanfile(thepath)
            return

    #walk the files and folders
    for dirpath, dirnames, filenames in os.walk(thepath):
        for f in filenames:
            # List of all files.
            managescanfile(os.path.join(dirpath, f))



if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print 'Missing the path to scan'
        sys.exit(1)

    processpath(sys.argv[1])


    #Do we need to wait for anything to complete scanning.
    while(len(watchlist) > 0):
        print 'Waiting for %d files to finish scanning.' % len(watchlist)
        for entry in watchlist:
            data = getfilestatusdata(entry.filename, entry.checksum)
            if(getprogresspercentage(data) == 100):
                watchlist.remove(entry)
                if(isscansuccessful(data) == False):
                    failedlist.append(entry)
                break;

    if(len(failedlist) > 0):
        print 'Scan failed for:\n'
        for entry in failedlist:
            print entry.filename
        sys.exit(1)

    print 'All files scanned successfully.'

    sys.exit(0)
