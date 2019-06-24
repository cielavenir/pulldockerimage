#!/usr/bin/env ruby
#coding:utf-8
#frozen_string_literal:true

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649

$verbose = true # verbose output in listing tags

require 'net/https'
require 'json'
require 'fileutils'
require 'digest/sha2'
require 'base64'
require 'uri'
require 'zlib'
require 'archive/tar/minitar' # gem install minitar

### ruby-mechanize (C) sparklemotion under MIT license.
### unless https://github.com/sparklemotion/mechanize/issues/495 is nicely resolved, we cannot install the gem safely.
### This defines Mechanize::HTTP::WWWAuthenticateParser class.
eval Zlib.inflate Base64.decode64 <<EOM
eNqlVttu00AQffdXDIbKTRucchGVQkzDTeIBEAIkHuIQbZ1pbNVZp7trAlTl29nZ8S0OFRI8WNmd+5w5s4rCqzJTGGijdCJk4CW5
0BreYZIKmf3Ep3x/8/nzh0r1vDTpRxT52hPGqIVCsUQFY52kuMZdWamyXYFyfku8gExmJhO5zQDsOQRrPQS2mLIMIqjCTq0SAKyA
Yk6dFd34kF1UfiiXLnoUQWFSVJ7G/CLkuqNaCEIumwy1MOQ76zhZq+M76zhjq2sT226EBrzKz6zWlZEKncJdGMtiWSRjbzatW526
XjnWPCSzpvRM6g0mpuPm3500mMOBhoMNxP6Bjv1nPhzALUEpnvvI9WUq8hzligD9ZFSZmFDiFsa153gjlFhre1Bi24659XOVzebg
7Dy2nrmfeVM4A0PjSYTGenDbFCUEL4TOkgCMvXhKZFb9XK3KNUrzWqlCDcHfqOJbtkTyh4tCgfMAUZKLyRJhskL6UMoctXZJGoaO
x0TO8bjBiHrrkgqOIRgFQyAuzAJXZjCvCnuVrVAbruy/Q2KusWqvE6rusJSXsthKt0q9xqrQcPeaDzc+obqL7EKKNVbQNymJ+W+I
ZERu1lnivP/89h1xDwRoozK5coiyusNUUyw00MBJxEP/8uXL87Yy/CCURsUrLJIEtS7cpgspUfXW2JtWcohAZnlT/IZiwHa7XYhO
ZC+pqaUhsszqen9yNX/iOyG/771NsxzBMhlhWXjnCsUlQVEHCbHQZ542QhmIWumm0G1eq9ifd5fzlNlr3iFKv6g4bTO1r0fwHleF
xcBg4FGiRVKs12KhNyJBRpvLY+qyY6f9sP/SkSNdOUAvF02WyUoKNqVbJx6Puds2/R6OwqPRgMrpmNrZQ7QH7szhNtyBbd6d12QC
zc2T+N0w8bnMMBGbzDhG3KF0zqBqngv2mgqvb3qDtJn685KCVu6byMtmCs7fKcKlXSh6be7Q9EkC0S8YfXXbcW+UeZyXNLfjxIdb
G+zTiuP8E4jMBIdKV041FPrfQoa6PD8cHQ6PB2dwdG80hCAYtJF4Feu0uW7eDwJkDhHj6gqq6LZDGgoMR4NjJs4ueXSz4H/2BPZi
k95e7FsPd8xNcYmybzL7Gp+cnNyPTx6dxg9OTw8Hk2fT4dNxHPvxKJ7F87Po+gbmFKZ54bpLy0EpfJdECk2pJIEEXapElfW+ut/l
UQS0VzU/u2TZIF4ePhi4vfWrpb0qC4PLBb/KPBHORDXvZ3NhG3m7CQ1SO/H+Xq5vSzW0j7akoLd7SVrKy/6zAR9xhd837hH2Z7GK
JcQmPnn8wH6P7ts5PIkf0lAenZ7Oj/3wnLaFA1G7nGsyYVF9azOs0CzOfxi0sHH60Pa12GYmPYMgjgP6w+Wwi6I9WBm87OI2PRew
l6q7Cy1cTG/+XJn1BarvNwSfzCQ=
EOM

def loggedin?(host)
	fname = ENV['HOME']+'/.docker/config.json'
	return nil if !File.exists?(fname)
	jso = JSON.parse(File.read(fname))
	credsStore = nil
	if (jso['credHelpers']||{})[host]
		credsStore = jso['credHelpers'][host]
	elsif jso['credsStore']
		credsStore = jso['credsStore']
	end
	if credsStore
		cmd = 'docker-credential-'+credsStore
		s = IO.popen([cmd,'get'],'r+b'){|io|
			io.write host
			io.close_write
			io.read
		}
		if $? == 0
			# docker-credential-pass always finishes successfully; need to check json
			jso = JSON.parse(s)
			return Base64.encode64(jso['Username']+':'+jso['Secret']) if (jso['Username']||'').size>0
		end
	end
	(jso['auths']||{}).include?(host) ? jso['auths'][host]['auth'] : nil
end

def ensureResponse(resp,auth)
	if ![301,302,307,308].include?(resp.code.to_i)
		yield resp
		return
	end
	resp.read_body
	loop{
		location = resp['location'].chomp
		locationurl = URI.parse(location)
		https = Net::HTTP.new(locationurl.host,locationurl.port)
		https.use_ssl = true
		https.verify_mode = OpenSSL::SSL::VERIFY_PEER
		https.start{
			https.request_get(locationurl.path+'?'+locationurl.query,auth){|resp|
				if ![301,302,307,308].include?(resp.code.to_i)
					yield resp
					return
				end
				resp.read_body
			}
		}
	}
end

def login(wwwAuth,repository)
	parser = Mechanize::HTTP::WWWAuthenticateParser.new.parse(wwwAuth)[0]
	uri = URI.parse(parser.params['realm'])
	authhttps = Net::HTTP.new(uri.host,uri.port)
	authhttps.use_ssl = true
	authhttps.verify_mode = OpenSSL::SSL::VERIFY_PEER
	authhttps.start{
		resp = authhttps.get(
			'%s?scope=repository:%s:pull&service=%s'%[uri.path,repository,parser.params['service']]
		)
		if resp.code.to_i == 401
			basic = loggedin?(uri.host)
			if basic
				account = Base64.decode64(basic).split(':')[0]
				resp = authhttps.get(
					'%s?account=%s&scope=repository:%s:pull&service=%s'%[uri.path,account,repository,parser.params['service']],
					'Authorization' => 'Basic '+basic
				)
				if resp.code.to_i == 401
					raise 'Credential is wrong. Please relogin to %s.'%uri.host
				end
			else
				raise '`docker login %s` is required.'%uri.host
			end
		end
		token = JSON.parse(resp.body)['token']
		return {'Authorization' => 'Bearer '+token}
	}
end

def pullDockerImage(arg,fout)
	tag = nil
	tagidx = arg.index('@')
	if !tagidx
		tagidx = arg.index(':')
	end
	if tagidx
		tag = arg[tagidx+1..-1]
		arg = arg[0,tagidx]
	end
	repository = arg
	host = repository.split('/')[0]
	repository = repository[host.size+1..-1]
	specified_by_digest = tag.index(':')

	https = Net::HTTP.new(host,443)
	https.use_ssl = true
	https.verify_mode = OpenSSL::SSL::VERIFY_PEER
	https.start{
		auth = {}
		if !tag
			resp = https.get('/v2/%s/tags/list'%repository,auth)
			if resp.code.to_i == 401
				auth = login(resp['www-authenticate'],repository)
				resp = https.get('/v2/%s/tags/list'%repository,auth)
			end
			tags = JSON.parse(resp.body)['tags'].sort
			tags.each{|tag|
				if $verbose
					if false
						resp = https.get(
							'/v2/%s/manifests/%s'%[repository,tag],
							auth.merge({
								'Accept' => 'application/vnd.docker.distribution.manifest.v1+json'
							})
						)
						repodigest = '---'
						created = JSON.parse(JSON.parse(resp.body)['history'][0]['v1Compatibility'])['created'].split('.')[0]
					else
						resp = https.get(
							'/v2/%s/manifests/%s'%[repository,tag],
							auth.merge({
								'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
							})
						)
						manifestv2 = JSON.parse(resp.body)
						repodigest = resp['docker-content-digest']
						created = nil
						begin
							https.request_get(
								'/v2/%s/blobs/%s'%[repository,manifestv2['config']['digest']],
								auth
							){|_resp|
								ensureResponse(_resp,auth){|resp|
									created = JSON.parse(resp.read_body)['created'].split('.')[0]
								}
							}
						rescue NoMethodError => e
							# manifest is unsupported format
							created = 'N/A'
						end
					end
					fout.puts "%s\t%s\t%s"%[tag,created,repodigest]
				else
					fout.puts tag
				end
			}
			return 0
		end

		resp = https.get(
			'/v2/%s/manifests/%s'%[repository,tag],
			auth.merge({
				'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
			})
		)
		if resp.code.to_i == 401
			auth = login(resp['www-authenticate'],repository)
			resp = https.get(
				'/v2/%s/manifests/%s'%[repository,tag],
				auth.merge({
					'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
				})
			)
		end

		manifestv2 = JSON.parse(resp.body)
		repodigest = resp['docker-content-digest']
		if resp['content-type'] != 'application/vnd.docker.distribution.manifest.v2+json'
			raise 'only manifest v2 is supported.'
		end
		Archive::Tar::Minitar::Output.open(fout){|output|
			tar = output.tar
			https.request_get(
				'/v2/%s/blobs/%s'%[repository,manifestv2['config']['digest']],
				auth
			){|_resp|
				ensureResponse(_resp,auth){|resp|
					#File.write(manifestv2['config']['digest'].split(':')[1]+'.json',resp.read_body)
					tar.add_file_simple(manifestv2['config']['digest'].split(':')[1]+'.json',{:data=>resp.read_body})
				}
			}
			manifestjson = {
				'Config' => manifestv2['config']['digest'].split(':')[1]+'.json',
				'RepoTags' => [
					'%s/%s:%s'%[host,repository,tag]
				],
				#'RepoDigests' => [
				#	'%s/%s@%s'%[host,repository,repodigest]
				#],
				'Layers' => []
			}
			if specified_by_digest
				manifestjson.delete('RepoTags')
			end
			layerId = ''
			manifestv2['layers'].each{|layer|
				layerDigest = layer['digest']
				parentId = layerId
				layerId = Digest::SHA256.hexdigest(parentId+"\n"+layerDigest+"\n")
				manifestjson['Layers'] << layerId+'/layer.tar'
				STDERR.puts '%s (%s)'%[layerId,layerDigest]
				#FileUtils.mkdir_p(layerId)
				#File.write(layerId+'/VERSION','1.0')
				tar.add_file_simple(layerId+'/VERSION',{:data=>'1.0'})
				#File.write(layerId+'/json',
				tar.add_file_simple(layerId+'/json',{:data=>
					JSON.generate({
						'id' => layerId,
						'parentId' => parentId,
						'created' => '0001-01-01T00:00:00Z',
						'container_config' => {
							'Hostname' => '',
							'Domainname' => '',
							'User' => '',
							'AttachStdin' => false,
							'AttachStdout' => false,
							'AttachStderr' => false,
							'Tty' => false,
							'OpenStdin' => false,
							'StdinOnce' => false,
							'Env' => nil,
							'Cmd' => nil,
							'Image' => '',
							'Volumes' => nil,
							'WorkingDir' => '',
							'Entrypoint' => nil,
							'OnBuild' => nil,
							'Labels' => nil,
						}
					})
				})

				https.request_get(
					'/v2/%s/blobs/%s'%[repository,layerDigest],
					auth
				){|_resp|
					ensureResponse(_resp,auth){|resp|
						#File.open(layerId+'/layer.tar','w'){|io|
						tar.add_file_simple(layerId+'/layer.tar',{:size=>resp['content-length'].to_i}){|io|
							resp.read_body{|body|io.write body}
						}
					}
				}
			}

			#File.write('manifest.json',JSON.generate([manifestjson]))
			tar.add_file_simple('manifest.json',{:data=>JSON.generate([manifestjson])})
			#File.write('repositories',
			tar.add_file_simple('repositories',{:data=>
				JSON.generate({
					host+'/'+repository => {tag => layerId} # This tag looks like the last layerId, according to manifest.json.
				})
			})
		}
	}
	return 0
end

if __FILE__ == $0
	if ARGV.size<1
		STDERR.puts <<EOM
pulldockerimage.rb host/repository:tag > archive.tar
eg: index.docker.io/library/ubuntu:devel > ubuntu.tar

generate a docker image directly (without deploying to the client machine).

`docker login` is required prior if authorization is required.
If credsStore is not used, .docker/config.json should look like this.

{
        "auths": {
                "auth.docker.io": {
                        "auth": base64(username:password)
                }
        }
}
EOM
		exit 1
	end
	exit pullDockerImage ARGV[0], STDOUT
end
