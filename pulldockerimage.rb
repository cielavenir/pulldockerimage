#!/usr/bin/env ruby
#coding:utf-8
#frozen_string_literal:true

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649
# https://github.com/mayflower/docker-ls

require 'net/https'
require 'json'
require 'fileutils'
require 'digest/sha2'
require 'base64'
require 'uri'
require 'zlib'
require 'archive/tar/minitar' # gem install minitar

begin
require 'mechanize'
rescue LoadError
### ruby-mechanize (C) sparklemotion under MIT license.
### unless https://github.com/sparklemotion/mechanize/issues/495 is nicely resolved, we cannot install the gem safely (need to make it optional).
### now mechanize -v '>=2.8.0' is safe but it requires Ruby 2.5 and not so compatible.
### This defines Mechanize::HTTP::WWWAuthenticateParser class.
if RUBY_VERSION >= '2.5'
	raise LoadError, 'Failed to require mechanize, it is optional only for Ruby<2.5 (the alternative implementation is insecure)'
end
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
end

def getCredential(host, b64=true)
	fname = ENV['HOME']+'/.docker/config.json'
	return nil if !File.file?(fname)
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
			if (jso['Username']||'').size>0
				if b64
					return Base64.strict_encode64(jso['Username']+':'+jso['Secret'])
				else
					return jso['Username']+':'+jso['Secret']
				end
			end
		end
	end
	if (jso['auths']||{}).include?(host)
		if b64
			return jso['auths'][host]['auth']
		else
			return Base64.decode64(jso['auths'][host]['auth'])
		end
	end
end

def ensureResponse(resp,auth_)
	auth = auth_.dup
	if ![301,302,307,308].include?(resp.code.to_i)
		yield resp
		return
	end
	resp.read_body
	loop{
		location = resp['location'].chomp
		locationurl = URI.parse(location)
		auth.delete('Authorization') if (locationurl.query||'').split('&').any?{|e|
			['X-Amz-Algorithm', 'Signature'].include? e.split('=')[0]
		}
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

def login(wwwAuth,host=nil,forceCredential=false)
	# puts wwwAuth
	parser = Mechanize::HTTP::WWWAuthenticateParser.new.parse(wwwAuth)[0]
	uri = URI.parse(parser.params['realm'])
	credentialHost = host || uri.host
	authhttps = Net::HTTP.new(uri.host,uri.port)
	authhttps.use_ssl = true
	authhttps.verify_mode = OpenSSL::SSL::VERIFY_PEER
	authhttps.start{
		resp = authhttps.get(
			# '%s?scope=repository:%s:pull&service=%s'%[uri.path,repository,parser.params['service']]
			'%s?scope=%s&service=%s'%[uri.path,parser.params['scope'],parser.params['service']]
		)
		if forceCredential || resp.code.to_i == 401 || resp.code.to_i == 403
			basic = getCredential(credentialHost)
			if basic
				account = Base64.decode64(basic).split(':')[0]
				resp = authhttps.get(
					'%s?account=%s&scope=%s&service=%s'%[uri.path,account,parser.params['scope'],parser.params['service']],
					'Authorization' => 'Basic '+basic
				)
				if resp.code.to_i == 401
					raise 'Credential is wrong (used "%s"). Please relogin to %s.'%[account,credentialHost]
				end
			else
				raise '`docker login %s` is required.'%credentialHost
			end
		end
		token = JSON.parse(resp.body)['token']
		return {'Authorization' => 'Bearer '+token}
	}
end

def ensureManifest(https, host, path, headers={}, auth=nil)
	if !auth
		auth = {}
	end
	resp = https.get(path,auth.merge(headers))
	if resp.code.to_i == 401
		auth = login(resp['www-authenticate'],host,false)
		resp = https.get(path,auth.merge(headers))
		if resp.code.to_i == 401
			STDERR.puts 'auth failed; probably got token for public image, forcing login to enter private image mode.'
			auth = login(resp['www-authenticate'],host,true)
			resp = https.get(path,auth.merge(headers))
		end
	end
	# if resp.code.to_i == 404
	# 	raise 'the specified repository (%s) does not exist on host (%s).'%[repository,host]
	# end
	if resp.code.to_i/100 != 2
		raise 'failed to retrieve manifest (%d).'%resp.code.to_i
	end
	return auth, resp
end

def pullDockerImage(arg,fout,kwargs)
	platform = kwargs['platform']
	verbose = kwargs['verbose']
	listing = kwargs['listing']
	touch = kwargs['touch']
	delete = kwargs['delete']

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
	specified_by_digest = tag && tag.index(':')

	https = Net::HTTP.new(host,443)
	https.use_ssl = true
	https.verify_mode = OpenSSL::SSL::VERIFY_PEER
	https.start{
		if !repository || repository == '' || repository == '/'
			auth = {}
			perPage = 100
			lastRepository = ''
			loop {
				auth, resp = ensureManifest(https, host, '/v2/_catalog?last=%s&n=%d' % [lastRepository, perPage], {}, auth)
				repositories = JSON.parse(resp.body)['repositories']
				repositories.sort.each{|repository|
					fout.puts repository
				}
				break if repositories.size < perPage
				lastRepository = repositories[-1]
			}
			return 0
		end

		if !tag || listing
			option_tag = tag
			auth, resp = ensureManifest(https, host, '/v2/%s/tags/list'%repository)
			tags = JSON.parse(resp.body)['tags'].sort
			tags.each{|tag|
				if !option_tag
					verbose = false
				elsif option_tag != tag
					next
				end
				if verbose
					if false
						resp = https.get(
							'/v2/%s/manifests/%s'%[repository,tag],
							auth.merge({
								'Accept' => 'application/vnd.docker.distribution.manifest.v1+json'
							})
						)
						repodigest = '---'
						created = JSON.parse(JSON.parse(resp.body)['history'][0]['v1Compatibility'])['created'].split('.')[0]
						fout.puts "%s\t%s\t%s"%[tag,created,repodigest]
					else
						resp = https.get(
							'/v2/%s/manifests/%s'%[repository,tag],
							auth.merge({
								'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
							})
						)
						manifestv2 = JSON.parse(resp.body)
						if ['application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.index.v1+json'].include?(resp['content-type'])
							manifestv2['manifests'].each{|manifest|
								# puts(manifest)
								resp = https.get(
									'/v2/%s/manifests/%s'%[repository,manifest['digest']],
									auth.merge({
										'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
									})
								)
								manifestManifest = JSON.parse(resp.body)
								begin
									https.request_get(
										'/v2/%s/blobs/%s'%[repository,manifestManifest['config']['digest']],
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
								fout.puts "%s(%s/%s)\t%s\t%s"%[tag,manifest['platform']['os'],manifest['platform']['architecture'],created,manifest['digest']]
							}
						else
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
							fout.puts "%s\t%s\t%s"%[tag,created,repodigest]
						end
					end
				else
					fout.puts tag
				end
			}
			return 0
		end

		auth, resp = ensureManifest(https, host, '/v2/%s/manifests/%s'%[repository,tag], {
			'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
		})
		manifestv2Json = resp.body
		manifestv2 = JSON.parse(manifestv2Json)
		repodigest = resp['docker-content-digest']
		if ['application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.index.v1+json'].include?(resp['content-type'])
			if manifestv2['manifests'].each{|manifest|
				if platform == '%s/%s' % [manifest['platform']['os'], manifest['platform']['architecture']]
					auth, resp = ensureManifest(https, host, '/v2/%s/manifests/%s'%[repository,manifest['digest']], {
						'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
					})
					manifestv2Json = resp.body
					manifestv2 = JSON.parse(manifestv2Json)
					break
				end
			}
				raise '%s manifest is a list but it does not contain proper image entry' % tag
			end
		end
		# ensure manifestv2 is right before proceeding anything
		if !['application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.oci.image.manifest.v1+json'].include?(resp['content-type'])
			raise 'only manifest v2 is supported (%s).' % resp['content-type']
		end
		if delete
			fout.puts 'DELETE /v2/%s/manifests/%s'%[repository,repodigest]
			resp = https.delete(
				'/v2/%s/manifests/%s'%[repository,repodigest],
				auth.merge({
					'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
				})
			)
			if resp.code.to_i == 401
				auth = login(resp['www-authenticate'],host,true)
				resp = https.delete(
					'/v2/%s/manifests/%s'%[repository,repodigest],
					auth.merge({
						'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
					})
				)
			end
			if resp.code.to_i/100 != 2
				raise 'failed delete manifest (%s)' % resp.body
			end
			fout.puts resp.body
			return 0
		end
		if touch
			fout.puts 'PUT /v2/%s/manifests/%s'%[repository,tag]
			resp = https.put(
				'/v2/%s/manifests/%s'%[repository,tag],
				manifestv2Json,
				auth.merge({
					'Content-Type' => 'application/vnd.docker.distribution.manifest.v2+json',
					'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
				})
			)
			if resp.code.to_i == 401
				auth = login(resp['www-authenticate'],host,true)
				resp = https.put(
					'/v2/%s/manifests/%s'%[repository,tag],
					manifestv2Json,
					auth.merge({
						'Content-Type' => 'application/vnd.docker.distribution.manifest.v2+json',
						'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
					})
				)
			end
			if resp.code.to_i/100 != 2
				raise 'failed touch manifest (%s)' % resp.body
			end
			fout.puts resp.body
			return 0
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
	require 'optparse'

	platform = 'linux/amd64'
	verbose = false
	listing = false
	touch = false
	delete = false

	banner = <<EOM
pulldockerimage.rb host/repository:tag > archive.tar
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

EOM

	opt = OptionParser.new(banner)
	opt.on('--platform PLATFORM', 'platform (%s)' % platform){|v|platform=v}
	opt.on('-v', '--verbose', 'verbose output in listing tags (note: massive amounts of request will be used)'){verbose=true}
	opt.on('-l', '--list', 'list images'){listing=true}
	opt.on('--touch', 'touch manifest'){touch=true}
	opt.on('--delete', 'delete image'){delete=true}
	opt.parse!(ARGV)

	if !ARGV[0]
		puts opt.help
		exit 0
	end
	exit pullDockerImage ARGV[0], STDOUT, {'platform'=>platform, 'verbose'=>verbose, 'listing'=>listing, 'touch'=>touch, 'delete'=>delete}
end
