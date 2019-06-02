## pulldockerimage

### Acknowledgement

- https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
- https://stackoverflow.com/a/47624649

### Credentials Store

Now [credentials store](https://docs.docker.com/engine/reference/commandline/login/#credentials-store) is supported.

### Article

https://qiita.com/cielavenir/items/c7e9db24dc6e4578e3c8

### Usage

```
pulldockerimage host/repository:tag > archive.tar
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
```
