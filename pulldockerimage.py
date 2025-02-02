#!/usr/bin/env python3
#coding:utf-8

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649
# https://github.com/mayflower/docker-ls

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

'''
try:
    import ujson as json  # print(ujson.dumps(['a/b'])) => ["a\/b"], weird backslash
except ImportError:
    import json
'''

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
    #     resp.read()
    #     raise Exception('the specified repository (%s) does not exist on host (%s).'%(repository,host))
    if int(resp.status)//100 != 2:
        resp.read()
        raise Exception('failed to retrieve manifest (%d).'%resp.status)
    return auth, resp

def pullDockerImage(arg,fout,platform=None,verbose=False,listing=False,touch=False,delete=False):
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

        if tag is None or listing:
            option_tag = tag
            auth, resp = ensureManifest(https, host, '/v2/%s/tags/list'%repository)
            for tag in sorted(json.load(resp)['tags']):
                if option_tag is None:
                    verbose = False
                elif option_tag != tag:
                    continue
                if verbose:
                    if False:
                        https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v1+json'))
                        resp = https.getresponse()
                        repodigest = '---'
                        created = json.loads(json.load(resp)['history'][0]['v1Compatibility'])['created'].split('.')[0]
                        fout.write(('%s\t%s\t%s\n'%(tag,created,repodigest)).encode('utf-8'))
                    else:
                        https.request('GET','/v2/%s/manifests/%s'%(repository,tag),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
                        resp = https.getresponse()
                        manifestv2 = json.load(resp)
                        if resp.getheader('content-type') in ['application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.index.v1+json']:
                            for manifest in manifestv2['manifests']:
                                # print(manifest)
                                https.request('GET','/v2/%s/manifests/%s'%(repository,manifest['digest']),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
                                resp = https.getresponse()
                                manifestManifest = json.load(resp)
                                try:
                                    https.request('GET','/v2/%s/blobs/%s'%(repository,manifestManifest['config']['digest']),None,auth)
                                    with ensureResponse(https,auth) as resp:
                                        data = json.load(resp)
                                        created = data['created'].split('.')[0]
                                except KeyError as e:
                                    # manifest is unsupported format
                                    created = 'N/A'
                                fout.write(('%s(%s/%s)\t%s\t%s\n'%(tag,manifest['platform'].get('os'),manifest['platform'].get('architecture'),created,manifest['digest'])).encode('utf-8'))
                        else:
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
        manifestv2Json = resp.read()
        manifestv2 = json.loads(manifestv2Json)
        repodigest = resp.getheader('docker-content-digest')
        if resp.getheader('content-type') in ['application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.index.v1+json']:
            for manifest in manifestv2['manifests']:
                if platform == '%s/%s' % (manifest['platform'].get('os'), manifest['platform'].get('architecture')):
                    auth, resp = ensureManifest(https, host, '/v2/%s/manifests/%s'%(repository,manifest['digest']), headers={'Accept':'application/vnd.docker.distribution.manifest.v2+json'})
                    manifestv2Json = resp.read()
                    manifestv2 = json.loads(manifestv2Json)
                    break
            else:
                raise Exception('%s manifest is a list but it does not contain proper image entry' % tag)
        # ensure manifestv2 is right before proceeding anything
        if resp.getheader('content-type') not in ['application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.oci.image.manifest.v1+json']:
            raise Exception('only manifest v2 is supported (%s).' % resp.getheader('content-type'))
        if delete:
            fout.write(('DELETE /v2/%s/manifests/%s\n'%(repository,repodigest)).encode('utf-8'))
            https.request('DELETE','/v2/%s/manifests/%s'%(repository,repodigest),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
            resp = https.getresponse()
            if resp.status == 401:
                resp.read()
                auth = login(resp.getheader('www-authenticate'),host,True)
                https.request('DELETE','/v2/%s/manifests/%s'%(repository,repodigest),None,dict(auth,Accept='application/vnd.docker.distribution.manifest.v2+json'))
                resp = https.getresponse()
            if int(resp.status)//100 != 2:
                raise Exception('failed delete manifest (%r)' % resp.read())
            fout.write(resp.read())
            fout.write(b'\n')
            return 0
        if touch:
            fout.write(('PUT /v2/%s/manifests/%s\n'%(repository,tag)).encode('utf-8'))
            https.request('PUT','/v2/%s/manifests/%s'%(repository,tag),manifestv2Json,dict(auth,**{'Content-Type':'application/vnd.docker.distribution.manifest.v2+json','Accept':'application/vnd.docker.distribution.manifest.v2+json'}))
            resp = https.getresponse()
            if resp.status == 401:
                resp.read()
                auth = login(resp.getheader('www-authenticate'),host,True)
                https.request('PUT','/v2/%s/manifests/%s'%(repository,tag),manifestv2Json,dict(auth,**{'Content-Type':'application/vnd.docker.distribution.manifest.v2+json','Accept':'application/vnd.docker.distribution.manifest.v2+json'}))
                resp = https.getresponse()
            if int(resp.status)//100 != 2:
                raise Exception('failed touch manifest (%r)' % resp.read())
            fout.write(resp.read())
            fout.write(b'\n')
            return 0
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
    import argparse
    description = '''
pulldockerimage.py host/repository:tag > archive.tar
eg: index.docker.io/library/ubuntu:devel > ubuntu.tar

generate a docker image directly (without deploying to the client machine).
'''.strip()

    epilog = '''
`docker login` is required prior if authorization is required.
If credsStore is not used, .docker/config.json should look like this.

{
        "auths": {
                "index.docker.io": {
                        "auth": base64(username:password)
                }
        }
}
'''.strip()

    platform_default = 'linux/amd64'

    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--platform',type=str,default=platform_default,help='platform (%s)'%platform_default)
    parser.add_argument('-v','--verbose',action='store_true',help='verbose output in listing tags (note: massive amounts of request will be used)')
    parser.add_argument('-l','--list',action='store_true',help='list images')
    parser.add_argument('--touch',action='store_true',help='touch manifest')
    parser.add_argument('--delete',action='store_true',help='delete image')
    parser.add_argument('image_tag')
    args = parser.parse_args(sys.argv[1:])
    exit(pullDockerImage(args.image_tag,binstdout,platform=args.platform,verbose=args.verbose,listing=args.list,touch=args.touch,delete=args.delete))
