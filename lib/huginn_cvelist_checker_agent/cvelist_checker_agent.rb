module Agents
  class CvelistCheckerAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule 'every_1h'

    description do
      <<-MD
      The Cvelist Checker agent fetches new commit and creates an event if a cve is public.

      `username` is used for github credentials.

      `token` is used for github credentials.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
            "CVE_data_meta": {
              "ASSIGNER": "cve@mitre.org",
              "ID": "CVE-2021-27983",
              "STATE": "PUBLIC"
            },
            "affects": {
              "vendor": {
                "vendor_data": [
                  {
                    "product": {
                      "product_data": [
                        {
                          "product_name": "n/a",
                          "version": {
                            "version_data": [
                              {
                                "version_value": "n/a"
                              }
                            ]
                          }
                        }
                      ]
                    },
                    "vendor_name": "n/a"
                  }
                ]
              }
            },
            "data_format": "MITRE",
            "data_type": "CVE",
            "data_version": "4.0",
            "description": {
              "description_data": [
                {
                  "lang": "eng",
                  "value": "Remote Code Execution (RCE) vulnerability exists in MaxSite CMS v107.5 via the Documents page."
                }
              ]
            },
            "problemtype": {
              "problemtype_data": [
                {
                  "description": [
                    {
                      "lang": "eng",
                      "value": "n/a"
                    }
                  ]
                }
              ]
            },
            "references": {
              "reference_data": [
                {
                  "url": "https://github.com/maxsite/cms/issues/430",
                  "refsource": "MISC",
                  "name": "https://github.com/maxsite/cms/issues/430"
                }
              ]
            }
          }
    MD

    def default_options
      {
        'debug' => 'false',
        'changes_only' => 'true'
      }
    end

    form_configurable :changes_only, type: :boolean
    form_configurable :username, type: :string
    form_configurable :token, type: :string
    form_configurable :debug, type: :boolean
    def validate_options
      unless options['username'].present?
        errors.add(:base, "username is a required field")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      unless options['token'].present?
        errors.add(:base, "token is a required field")
      end
    end

    def working?
      !recent_error_logs?
    end

    def check
      fetch
    end

    private

    def get_json(url)
      uri = URI.parse(url)
      request = Net::HTTP::Get.new(uri)
      request.basic_auth("#{interpolated[:username]}", "#{interpolated[:token]}")
    
      req_options = {
        use_ssl: uri.scheme == "https",
      }
    
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    
      log "fetch event request status : #{response.code}"
    
      payload = JSON.parse(response.body)

      if interpolated['debug'] == 'true'
        log "payload"
        log payload
      end
      content = Base64.decode64(payload['content'])
      parsed_content = JSON.parse(content)
      if parsed_content['CVE_data_meta']['STATE'] == "PUBLIC"
        create_event payload: parsed_content
      end
    end

    def get_commit(commit)
      uri = URI.parse(commit)
      request = Net::HTTP::Get.new(uri)
      request.basic_auth("#{interpolated[:username]}", "#{interpolated[:token]}")
    
      req_options = {
        use_ssl: uri.scheme == "https",
      }
    
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    
      log "fetch event request status : #{response.code}"
    
      payload = JSON.parse(response.body)

      if interpolated['debug'] == 'true'
        log "payload"
        log payload
      end
      get_json(payload['files'][0]['contents_url'])
    end    
    
    def fetch
      uri = URI.parse("https://api.github.com/repos/CVEProject/cvelist/commits")
      request = Net::HTTP::Get.new(uri)
      request.basic_auth("#{interpolated[:username]}", "#{interpolated[:token]}")
    
      req_options = {
        use_ssl: uri.scheme == "https",
      }
    
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    
      log "fetch event request status : #{response.code}"
    
      payload = JSON.parse(response.body)

      if interpolated['debug'] == 'true'
        log "payload"
        log payload
      end

      if interpolated['changes_only'] == 'true' && !payload.empty?
        if payload.to_s != memory['last_status']
          if payload
            if "#{memory['last_status']}" == ''
              payload.each do |commit|
                if interpolated['debug'] == 'true'
                  log "commit"
                  log commit
                end
                get_commit(commit['url'])
              end
            else
              last_status = memory['last_status']
              payload.each do |commit|
                found = false
                if interpolated['debug'] == 'true'
                  log "found is #{found}!"
                  log commit
                end
                last_status.each do |sha|
                  if commit['sha'] == sha
                    found = true
                  end
                  if interpolated['debug'] == 'true'
                    log "found is #{found}!"
                  end
                end
                if found == false
                  if interpolated['debug'] == 'true'
                    log "found is #{found}! so commit created"
                    log commit
                  end
                  get_commit(commit['url'])
                end
              end
            end
          end
          memory['last_status'] = payload.map{|x| x['sha']}
        end
      else
        if !payload.empty?
          create_event payload: payload
          if payload.to_s != memory['last_status']
            memory['last_status'] = payload
          end
        end
      end
    end
  end
end
