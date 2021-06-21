class Consumer::AwsSigv4Controller < ActionController::Base
  include Consumer::Common::Filters
  before_action :set_user, :set_locale, :ensure_consumer_access
  before_action :cors_preflight_check if Rails.env.qa2? || Rails.env.qa4? || Rails.env.preprod?
  after_action :cors_set_access_control_headers if Rails.env.qa2? || Rails.env.qa4? || Rails.env.preprod?

  def livestream
    live_debug = params[:live_debug].present? && params[:live_debug] == "true"
    if live_debug
      response = start_live_debug
      live_topic = ProvisionApi.get_topics(params[:serial_num])['live_debug_json']
    else
      response = start_livestream
      live_topic = ProvisionApi.get_topics(params[:serial_num])['live'] rescue nil
    end

    unless response
      render json: {message: "Envoy not found!"}, status: 404
      return
    end

    unless live_topic
      render json: { message: "Provision Api failed to get topics" }, status: 404
      return
    end

    signed_url = generate_signed_mqtt_url
    return render json: { signed_url: signed_url, live_stream_duration: APP_CONFIG[:mqtt][:live_stream_duration], live_stream_topic: live_topic  }, status: 200 unless live_debug
    render json: { signed_url: signed_url, live_debug_duration: APP_CONFIG[:mqtt][:live_debug_duration], live_debug_topic: live_topic  }, status: 200
  end

  def get_mqtt_signed_url
    signed_url = generate_signed_mqtt_url
    render json: { signed_url: signed_url }, status: 200
  end

  def generate_signed_mqtt_url
    region_name = ENV['AWS_REGION'] || 'us-east-1'
    aws_Iot_endpoint =ENV['AWS_IOT_ENDPOINT'] || 'a27n5wopct95hi-ats.iot.us-east-1.amazonaws.com'
    secret_key = ENV['AWS_SECRET_ACCESS_KEY']
    signed_url = create_endpoint(region_name, aws_Iot_endpoint, secret_key)
  end

  def start_livestream
    envoy = Envoy.active.find_by_serial_num(params[:serial_num]) if params[:serial_num]
    if envoy && authorize!(:read, envoy.site)
      current_time = Time.now.to_i * 1000
      CommandControl.send_command({
                                      gateways: [envoy.try(:serial_num)],
                                      commands: [{
                                                     command_operation: "schedule",
                                                     issue_time: current_time,
                                                     command_type: "ReportCtrlCmd",
                                                     payload: {
                                                         settings: [{
                                                                        rpttype: 0,
                                                                        durationSec: APP_CONFIG[:mqtt][:live_stream_duration],
                                                                        devices: ["DEVICE1", "DEVICE2", "DEVICE_ID_0"]
                                                                    }]
                                                     }
                                                 }]
                                  })
      return true
    end
    return false
  end

  def generator_toggle
    envoy = Envoy.active.find_by_serial_num(params[:serial_num]) if params[:serial_num]
    state = params[:state]
    return false unless state
    state = state.eql?("on") ? 2 : 1 # If 'on', send state '2'. Otherwise, send '1'
    if envoy && authorize!(:read, envoy.site)
      current_time = Time.now.to_i * 1000
      CommandControl.send_command({
                                      gateways: [envoy.try(:serial_num)],
                                      commands: [{
                                                     command_operation: "schedule",
                                                     issue_time: current_time,
                                                     command_type: "GenRelayCtrlCmd",
                                                     payload: {
                                                         state: state
                                                     }
                                                 }]
                                  })
      AuditLog.create_audit_log_entry(Info::GeneratorConfig, envoy.site_id, "Turn #{params[:state]} Request", [ {state: [nil, params[:state]]}, {app_name: [nil, "Enlighten Mobile"]} ] )
      return true
    end
    return false
  end

  def dry_contact
    envoy = Envoy.active.find_by_serial_num(params[:serial_num]) if params[:serial_num]
    state = params[:state]
    id = params[:id]
    return false unless state && id
    state = case state
            when "invalid"
              0
            when "off"
              1
            when "on"
              2
            end
    id = case id
         when "NC1"
           0
         when "NC2"
           1
         when "NO1"
           2
         when "NO2"
           3
         end
    if envoy && authorize!(:read, envoy.site)
      current_time = Time.now.to_i * 1000
      CommandControl.send_command({
                                      gateways: [envoy.try(:serial_num)],
                                      commands: [{
                                                     command_operation: "schedule",
                                                     issue_time: current_time,
                                                     command_type: "DryContactCtrlCmd",
                                                     payload: {
                                                         state: state,
                                                         id: id
                                                     }
                                                 }]
                                  })
      return true
    end
    return false
  end

  def start_live_debug
    envoy = Envoy.active.find_by_serial_num(params[:serial_num]) if params[:serial_num]
    if envoy && authorize!(:read, envoy.site)
      current_time = Time.now.to_i * 1000
      CommandControl.send_command({
                                      gateways: [envoy.try(:serial_num)],
                                      commands: [{
                                                     command_operation: "schedule",
                                                     issue_time: current_time,
                                                     command_type: "LiveDebugCmd",
                                                     payload: {
                                                         mode: 0,
                                                         duration: 900
                                                     }
                                                 }]
                                  })
      return true
    end
    return false
  end

  private

  def get_signature_key(region_name, secret_key, date_stamp, service_name, string_to_sign)
    k_date = hmac('AWS4' + secret_key, toDate(date_stamp))
    k_region = hmac(k_date, region_name)
    k_service = hmac(k_region, service_name)
    k_credentials = hmac(k_service, 'aws4_request')
    hexhmac(k_credentials, string_to_sign)
  end

  def create_endpoint(region_name, aws_Iot_endpoint, secret_key)
    # Task 1: Create a Canonical Request For Signature Version 4
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    date_stamp = Time.now.utc.to_i
    amzdate = toTime(date_stamp)
    service = 'iotdevicegateway'
    method = 'GET'
    canonical_uri = '/mqtt'
    host = aws_Iot_endpoint
    credential_scope = toDate(date_stamp) + '/' + region_name + '/' + service + '/' + 'aws4_request'
    canonical_query_string = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
    canonical_query_string += '&X-Amz-Credential=' + URI.encode_www_form_component(ENV['AWS_ACCESS_KEY_ID'] + '/' + credential_scope)
    canonical_query_string += '&X-Amz-Date=' + amzdate
    canonical_query_string += '&X-Amz-Expires=6000'
    canonical_query_string += '&X-Amz-SignedHeaders=host'
    payload_hash = hexdigest("")
    canonical_headers = "host:#{host}"

    # Task 2: Create a String to Sign for Signature Version 4
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    canonical_request =  "#{method}\n#{canonical_uri}\n#{canonical_query_string}\n#{canonical_headers}\n\nhost\n#{payload_hash}"
    algorithm = 'AWS4-HMAC-SHA256'
    string_to_sign = "#{algorithm}\n#{amzdate}\n#{credential_scope}\n#{hexdigest(canonical_request)}"

    # Task 3: Calculate the AWS Signature Version 4
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    signing_key = get_signature_key(region_name, secret_key, date_stamp, service, string_to_sign)

    # Task 4: Add the Signing Information to the Request
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
    signature = signing_key
    canonical_query_string += '&X-Amz-Signature=' + signature
    'wss://' + host + canonical_uri + '?' + canonical_query_string
  end

  def hexdigest(value)
    Digest::SHA256.new.update(value).hexdigest
  end

  def hmac(key, value)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, value)
  end

  def hexhmac(key, value)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, value)
  end

  def toTime(time)
    Time.at(time).utc.iso8601.gsub(/[:\-]|\.\d{3}/, "")
  end

  def toDate(time)
    toTime(time)[0,8]
  end

  def current_user
    return @user if @user.present?
  end

  # For all responses in this controller, return the CORS access control headers.

  def cors_set_access_control_headers
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'POST, PUT, DELETE, GET, OPTIONS'
    headers['Access-Control-Max-Age'] = "1728000"
  end

  # If this is a preflight OPTIONS request, then short-circuit the
  # request, return only the necessary headers and return an empty
  # text/plain.

  def cors_preflight_check
    if request.method == "OPTIONS"
      headers['Access-Control-Allow-Origin'] = '*'
      headers['Access-Control-Allow-Methods'] = 'POST, PUT, DELETE, GET, OPTIONS'
      headers['Access-Control-Allow-Headers'] = 'Authorization,DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,X-Prototype-Version,If-Modified-Since,Cache-Control,Content-Type'
      headers['Access-Control-Max-Age'] = '1728000'
      render :body => nil, :status => 204
    end
  end
end
