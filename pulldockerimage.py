#!/usr/bin/env python
#coding:utf-8

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649

import os
import sys
import base64
import hashlib
import tarfile
from contextlib import closing

if sys.version_info[0]>=3:
    import http.client as httplib
    from io import BytesIO
    binstdout = sys.stdout.buffer
else:
    import httplib
    from cStringIO import StringIO
    BytesIO = StringIO
    binstdout = sys.stdout

try:
    import ujson as json
except ImportError:
    import json

def loggedin(host):
    fname = os.environ['HOME']+'/.docker/config.json'
    if os.path.exists(fname):
        jso = json.load(open(fname))
        if host in jso['auths']:
            return jso['auths'][host]['auth']

def makeTarInfo(**kwargs):
    info = tarfile.TarInfo(kwargs.pop('name'))
    if 'data' in kwargs:
        info.size = len(kwargs.pop('data'))
    for k in kwargs:
        setattr(info,k,kwargs[k])
    return info

if len(sys.argv)<2:
    sys.stderr.write('pulldockerimage.py host/repository:tag > archive.tar\n')
    sys.stderr.write('generate a docker image directly (without deploying to the host machine)\n')
    exit()

repository = sys.argv[1].split(':')[0]
host = repository.split('/')[0]
repository = repository[len(host)+1:]
tag = sys.argv[1].split(':')[1]

with closing(httplib.HTTPSConnection(host)) as https:
    auth = {}
    basic = loggedin(host)
    if basic:
        account = base64.b64decode(basic).decode('utf-8').split(':')[0]
        https.request('GET','/auth?account=%s&scope=repository:%s:pull&service=%s'%(account,repository,host),None,{'Authorization':'Basic '+basic})
        resp = https.getresponse()
        token = json.load(resp)['token']
        auth = {'Authorization':'Bearer '+token}
    https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
    resp = https.getresponse()
    manifestv2 = json.load(resp)
    
    with tarfile.open(mode='w|',fileobj=binstdout) as tar:
        https.request('GET','/v2/%s/blobs/%s'%(repository,manifestv2['config']['digest']),None,auth)
        resp = https.getresponse()
        tar.addfile(makeTarInfo(
            name=manifestv2['config']['digest'].split(':')[1]+'.json',
            size=int(resp.getheader('content-length'))
        ),resp)
        manifestjson = {
            'Config' : manifestv2['config']['digest'].split(':')[1]+'.json',
            'Repotags' : [
                '%s/%s:%s'%(host,repository,tag)
            ],
            'Layers' : []
        }
        layerId = ''
        for layer in manifestv2['layers']:
            layerDigest = layer['digest']
            parentId = layerId
            layerId = hashlib.sha256((parentId+'\n'+layerDigest+'\n').encode('utf-8')).hexdigest()
            manifestjson['Layers'].append(layerId+'/layer.tar')
            sys.stderr.write('%s (%s)\n'%(layerId,layerDigest))
            tar.addfile(makeTarInfo(name=layerId+'/VERSION',size=3),BytesIO('1.0'.encode('utf-8')))
            jsonstr = json.dumps({
                'id' : layerId,
                'parentId' : parentId,
                'created' : '0001-01-01T00:00:00Z',
                'container_config' : {
                    'Hostname' : '',
                    'Domainname' : '',
                    'User' : '',
                    'AttachStdin' : False,
                    'AttachStdout' : False,
                    'AttachStderr' : False,
                    'Tty' : False,
                    'OpenStdin' : False,
                    'StdinOnce' : False,
                    'Env' : None,
                    'Cmd' : None,
                    'Image' : '',
                    'Volumes' : None,
                    'WorkingDir' : '',
                    'Entrypoint' : None,
                    'OnBuild' : None,
                    'Labels' : None,
                }
            })
            tar.addfile(makeTarInfo(name=layerId+'/json',data=jsonstr),BytesIO(jsonstr.encode('utf-8')))
            https.request('GET','/v2/%s/blobs/%s'%(repository,layerDigest),None,auth)
            resp = https.getresponse()
            tar.addfile(makeTarInfo(
                name=layerId+'/layer.tar',
                size=int(resp.getheader('content-length'))
            ),resp)
        manifestjsonstr = json.dumps([manifestjson])
        tar.addfile(makeTarInfo(name='manifest.json',data=manifestjsonstr),BytesIO(manifestjsonstr.encode('utf-8')))
        repositoryjsonstr = json.dumps({
            host+'/'+repository : {tag : ''}
        })
        tar.addfile(makeTarInfo(name='repositories',data=repositoryjsonstr),BytesIO(repositoryjsonstr.encode('utf-8')))

