#!/usr/bin/env python
#coding:utf-8

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649

verbose = True # verbose output in listing tags

import os
import sys
import base64
import hashlib
import tarfile
import subprocess
from contextlib import closing, contextmanager

if sys.version_info[0]>=3:
    import http.client as httplib
    from urllib.request import parse_http_list, parse_keqv_list
    from urllib.parse import urlparse
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

def getCredential(host, b64=True):
    fname = os.environ['HOME']+'/.docker/config.json'
    if os.path.isfile(fname):
        with open(fname) as f:
            jso = json.load(f)
            credsStore = None
            if host in jso.get('credHelpers',{}):
                credsStore = jso['credHelpers'][host]
            elif 'credsStore' in jso:
                credsStore = jso['credsStore']
            if credsStore is not None:
                cmd = 'docker-credential-'+credsStore
                proc = subprocess.Popen([cmd,'get'],shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=-1)
                outs, errs = proc.communicate(host.encode('utf-8'))
                if proc.returncode == 0:
                    # docker-credential-pass always finishes successfully; need to check json
                    jso = json.loads(outs.decode('utf-8'))
                    if jso.get('Username'):
                        if b64:
                            return base64.b64encode((jso['Username']+':'+jso['Secret']).encode('utf-8')).decode('utf-8')
                        else:
                            return jso['Username']+':'+jso['Secret']
            if host in jso.get('auths',{}):
                if b64:
                    return jso['auths'][host]['auth']
                else:
                    return base64.b64decode(jso['auths'][host]['auth'].encode('utf-8')).decode('utf-8')

def makeTarInfo(**kwargs):
    info = tarfile.TarInfo(kwargs.pop('name'))
    if 'data' in kwargs:
        info.size = len(kwargs.pop('data'))
    for k in kwargs:
        setattr(info,k,kwargs[k])
    return info

@contextmanager
def ensureResponse(https,auth_):
    auth = dict(auth_)
    resp = https.getresponse()
    if resp.status not in [301,302,307,308]:
        yield resp
        return
    resp.read()
    while True:
        location = resp.getheader('location')
        locationurl = urlparse(location)
        if any(e.split('=')[0] in ['X-Amz-Algorithm', 'Signature'] for e in (locationurl.query or '').split('&')):
            auth.pop('Authorization', None)
        with closing(httplib.HTTPSConnection(locationurl.netloc)) as https:
            https.request('GET',locationurl.path+'?'+locationurl.query,None,auth)
            resp = https.getresponse()
            if resp.status not in [301,302,307,308]:
                yield resp
                return
            resp.read()

def login(wwwAuth,host=None,forceCredential=False):
    authresp = wwwAuth
    # print(wwwAuth)
    realm = parse_keqv_list(parse_http_list(authresp[authresp.index(' ')+1:]))
    realmurl = urlparse(realm['realm'])
    credentialHost = host if host is not None else realmurl.netloc
    with closing(httplib.HTTPSConnection(realmurl.netloc)) as authhttps:
        #authhttps.request('GET','%s?scope=repository:%s:pull&service=%s'%(realmurl.path,repository,realm['service']),None)
        authhttps.request('GET','%s?scope=%s&service=%s'%(realmurl.path,realm['scope'],realm['service']),None)
        resp = authhttps.getresponse()
        if forceCredential or resp.status == 401 or resp.status == 403:
            resp.read()
            basic = getCredential(credentialHost)
            if basic:
                account = base64.b64decode(basic).decode('utf-8').split(':')[0]
                authhttps.request('GET','%s?account=%s&scope=%s&service=%s'%(realmurl.path,account,realm['scope'],realm['service']),None,{'Authorization':'Basic '+basic})
                resp = authhttps.getresponse()
                if resp.status == 401:
                    raise Exception('Credential is wrong (used "%s"). Please relogin to %s.'%(account,credentialHost))
            else:
                raise Exception('`docker login %s` is required.'%(credentialHost))
        if int(resp.status)//100 == 5:
            raise Exception('failed to get login token (status %d): %s'%(int(resp.status), resp.read()))
        token = json.load(resp)['token']
        return {'Authorization':'Bearer '+token}

def ensureManifest(https, host, path, headers={}, auth=None):
    if auth is None:
        auth = {}
    https.request('GET',path,None,dict(auth,**headers))
    resp = https.getresponse()
    if resp.status == 401:
        resp.read()
        auth = login(resp.getheader('www-authenticate'),host,False)
        https.request('GET',path,None,dict(auth,**headers))
        resp = https.getresponse()
        if resp.status == 401:
            sys.stderr.write('auth failed; probably got token for public image, forcing login to enter private image mode.\n')
            resp.read()
            auth = login(resp.getheader('www-authenticate'),host,True)
            https.request('GET',path,None,dict(auth,**headers))
            resp = https.getresponse()
    # if resp.status == 404:
    #     raise Exception('the specified repository (%s) does not exist on host (%s).'%(repository,host))
    if int(resp.status)//100 != 2:
        raise Exception('failed to retrieve manifest (%d).'%resp.status)
    return auth, resp

def pullDockerImage(arg,fout):
    tag = None
    tagidx = arg.find('@')
    if tagidx < 0:
        tagidx = arg.find(':')
    if tagidx >= 0:
        tag = arg[tagidx+1:]
        arg = arg[:tagidx]
    repository = arg
    host = repository.split('/')[0]
    repository = repository[len(host)+1:]
    specified_by_digest = tag is not None and tag.find(':')>=0

    with closing(httplib.HTTPSConnection(host)) as https:
        if repository == '' or repository == '/':
            auth = {}
            perPage = 100
            lastRepository = ''
            while True:
                auth, resp = ensureManifest(https, host, '/v2/_catalog?last=%s&n=%d' % (lastRepository, perPage), headers={}, auth=auth)
                repositories = json.load(resp)['repositories']
                for repository in sorted(repositories):
                    fout.write(('%s\n'%repository).encode('utf-8'))
                if len(repositories) < perPage:
                    break
                lastRepository = repositories[-1]
            return 0

        if tag is None:
            auth, resp = ensureManifest(https, host, '/v2/%s/tags/list'%repository)
            for tag in sorted(json.load(resp)['tags']):
                if verbose:
                    if False:
                        https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v1+json'))
                        resp = https.getresponse()
                        repodigest = '---'
                        created = json.loads(json.load(resp)['history'][0]['v1Compatibility'])['created'].split('.')[0]
                    else:
                        https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
                        resp = https.getresponse()
                        manifestv2 = json.load(resp)
                        repodigest = resp.getheader('docker-content-digest') or '---'
                        try:
                            https.request('GET','/v2/%s/blobs/%s'%(repository,manifestv2['config']['digest']),None,auth)
                            with ensureResponse(https,auth) as resp:
                                created = json.load(resp)['created'].split('.')[0]
                        except KeyError as e:
                            # manifest is unsupported format
                            created = 'N/A'
                    fout.write(('%s\t%s\t%s\n'%(tag,created,repodigest)).encode('utf-8'))
                else:
                    fout.write(('%s\n'%tag).encode('utf-8'))
            return 0

        auth, resp = ensureManifest(https, host, '/v2/%s/manifests/%s'%(repository,tag), headers={'Accept':'application/vnd.docker.distribution.manifest.v2+json'})
        manifestv2 = json.load(resp)
        repodigest = resp.getheader('docker-content-digest')
        if resp.getheader('content-type') != 'application/vnd.docker.distribution.manifest.v2+json':
            raise Exception('only manifest v2 is supported.')
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
                #'RepoDigests' : [
                #    '%s/%s@%s'%(host,repository,repodigest)
                #],
                'Layers' : []
            }
            if specified_by_digest:
                del manifestjson['RepoTags']
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
                host+'/'+repository : {tag : layerId} # This tag looks like the last layerId, according to manifest.json.
            })
            tar.addfile(makeTarInfo(name='repositories',data=repositoryjsonstr),BytesIO(repositoryjsonstr.encode('utf-8')))

    return 0

if __name__ == '__main__':
    if len(sys.argv)<2:
        sys.stderr.write(
'''pulldockerimage.py host/repository:tag > archive.tar
eg: index.docker.io/library/ubuntu:devel > ubuntu.tar

generate a docker image directly (without deploying to the client machine).

`docker login` is required prior if authorization is required.
If credsStore is not used, .docker/config.json should look like this.

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
