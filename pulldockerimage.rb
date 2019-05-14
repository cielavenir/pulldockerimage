#!/usr/bin/env ruby
#coding:utf-8
#frozen_string_literal:true

# acknowledgement:
# https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh
# https://stackoverflow.com/a/47624649

require 'net/https'
require 'json'
require 'fileutils'
require 'digest/sha2'
require 'base64'
require 'archive/tar/minitar' # gem install minitar

def loggedin?(host)
	fname = ENV['HOME']+'/.docker/config.json'
	return nil if !File.exists?(fname)
	jso = JSON.parse(File.read(fname))
	jso['auths'].include?(host) ? jso['auths'][host]['auth'] : nil
end

if ARGV.size<1
	STDERR.puts 'pulldockerimage.rb host/repository:tag > archive.tar'
	STDERR.puts 'generate a docker image directly (without deploying to the host machine)'
	exit
end

repository = ARGV[0].split(':')[0]
host = repository.split('/')[0]
repository = repository[host.size+1..-1]
tag = ARGV[0].split(':')[1]

https = Net::HTTP.new(host,443)
https.use_ssl = true
https.verify_mode = OpenSSL::SSL::VERIFY_PEER
https.start{
	auth = {}
        basic = loggedin?(host)
	if basic
		account = Base64.decode64(basic).split(':')[0]
		resp = https.get(
			'/auth?account=%s&scope=repository:%s:pull&service=%s'%[account,repository,host],
			'Authorization' => 'Basic '+basic
        	)
		token = JSON.parse(resp.body)['token']
		auth = {'Authorization' => 'Bearer '+token}
	end
	resp = https.get(
		'/v2/%s/manifests/%s'%[repository,tag],
		auth.merge({
			'Accept' => 'application/vnd.docker.distribution.manifest.v2+json'
		})
	)
	manifestv2 = JSON.parse(resp.body)
	Archive::Tar::Minitar::Output.open(STDOUT){|output|
		tar = output.tar
		resp = https.get(
			'/v2/%s/blobs/%s'%[repository,manifestv2['config']['digest']],
			auth
		)
		#File.write(manifestv2['config']['digest'].split(':')[1]+'.json',resp.body)
		tar.add_file_simple(manifestv2['config']['digest'].split(':')[1]+'.json',{:data=>resp.body})
		manifestjson = {
			'Config' => manifestv2['config']['digest'].split(':')[1]+'.json',
			'Repotags' => [
				'%s/%s:%s'%[host,repository,tag]
			],
			'Layers' => []
		}
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
			){|resp|
				#File.open(layerId+'/layer.tar','w'){|io|
				tar.add_file_simple(layerId+'/layer.tar',{:size=>resp['content-length'].to_i}){|io|
					resp.read_body{|body|io.write body}
				}
			}
		}

		#File.write('manifest.json',JSON.generate([manifestjson]))
		tar.add_file_simple('manifest.json',{:data=>JSON.generate([manifestjson])})
        	#File.write('repositories',
		tar.add_file_simple('repositories',{:data=>
			JSON.generate({
				host+'/'+repository => {tag => ''}
			})
		})
	}
}
