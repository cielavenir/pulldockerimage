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
import subprocess
from contextlib import closing, contextmanager

if sys.version_info[0]>=3:
    import http.client as httplib
    from urllib.request import parse_http_list, parse_keqv_list, urlparse
    from io import BytesIO
    binstdout = sys.stdout.buffer
else:
    import httplib
    from urllib2 import parse_http_list, parse_keqv_list
    from urlparse import urlparse
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
        with open(fname) as f:
            jso = json.load(f)
            credsStore = None
            if host in jso.get('credHelpers',{}):
                credsStore = jso['credHelpers'][host]
            elif 'credsStore' in jso:
                credsStore = jso['credsStore']
            if credsStore is not None:
                cmd = 'docker-credential-'+credsStore
                proc = subprocess.Popen([cmd,'get'],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                outs, errs = proc.communicate(host.encode('utf-8'))
                if proc.returncode == 0:
                    jso = json.loads(outs.decode('utf-8'))
                    return base64.b64encode((jso['Username']+':'+jso['Secret']).encode('utf-8')).decode('utf-8')
            if host in jso.get('auths',{}):
                return jso['auths'][host]['auth']

def makeTarInfo(**kwargs):
    info = tarfile.TarInfo(kwargs.pop('name'))
    if 'data' in kwargs:
        info.size = len(kwargs.pop('data'))
    for k in kwargs:
        setattr(info,k,kwargs[k])
    return info

@contextmanager
def ensureResponse(https,auth):
    resp = https.getresponse()
    if resp.status not in [301,302,307,308]:
        yield resp
        return
    resp.read()
    while True:
        location = resp.getheader('location')
        locationurl = urlparse(location)
        with closing(httplib.HTTPSConnection(locationurl.netloc)) as https:
            https.request('GET',locationurl.path+'?'+locationurl.query,None,auth)
            resp = https.getresponse()
            if resp.status not in [301,302,307,308]:
                yield resp
                return
            resp.read()

def pullDockerImage(arg,fout):
    repository = arg.split(':')[0]
    host = repository.split('/')[0]
    repository = repository[len(host)+1:]
    tag = arg.split(':')[1]

    with closing(httplib.HTTPSConnection(host)) as https:
        auth = {}
        https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
        resp = https.getresponse()
        if resp.status == 401:
            resp.read()
            authresp = resp.getheader('www-authenticate')
            realm = parse_keqv_list(parse_http_list(authresp[authresp.index(' ')+1:]))
            realmurl = urlparse(realm['realm'])
            basic = loggedin(realmurl.netloc)
            if basic:
                account = base64.b64decode(basic).decode('utf-8').split(':')[0]
                with closing(httplib.HTTPSConnection(realmurl.netloc)) as authhttps:
                    authhttps.request('GET','%s?account=%s&scope=repository:%s:pull&service=%s'%(realmurl.path,account,repository,realm['service']),None,{'Authorization':'Basic '+basic})
                    resp = authhttps.getresponse()
                    if resp.status == 401:
                        raise Exception('Credential is wrong. Please relogin to %s.'%realmurl.hostname)
                    token = json.load(resp)['token']
                    auth = {'Authorization':'Bearer '+token}
            else:
                raise Exception('`docker login %s` is required.'%realmurl.hostname)

            https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
            resp = https.getresponse()

        manifestv2 = json.load(resp)
        with tarfile.open(mode='w|',fileobj=fout) as tar:
            https.request('GET','/v2/%s/blobs/%s'%(repository,manifestv2['config']['digest']),None,auth)
            with ensureResponse(https,auth) as resp:
                tar.addfile(makeTarInfo(
                    name=manifestv2['config']['digest'].split(':')[1]+'.json',
                    size=int(resp.getheader('content-length'))
                ),resp)
            manifestjson = {
                'Config' : manifestv2['config']['digest'].split(':')[1]+'.json',
                'RepoTags' : [
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
                with ensureResponse(https,auth) as resp:
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

    return 0

if __name__ == '__main__':
    if len(sys.argv)<2:
        sys.stderr.write(
'''pulldockerimage.py host/repository:tag > archive.tar
eg: index.docker.io/library/ubuntu:devel > ubuntu.tar

generate a docker image directly (without deploying to the client machine).

`docker login` is required prior. If credsStore is not used, .docker/config.json should look like this.

{
        "auths": {
                "index.docker.io": {
                        "auth": base64(username:password)
                }
        }
}
''')
        exit(1)
    exit(pullDockerImage(sys.argv[1],binstdout))
