require "logstash/codecs/base"
require "logstash/codecs/line"

class LogStash::Codecs::CEF < LogStash::Codecs::Base
  config_name "cef"

  milestone 1

  # Specify if the Syslog header will be expected
  config :syslog, :validate => :boolean, :default => false

  config :signature, :validate => :string, :default => "Logstash"
  config :name, :validate => :string, :default => "Logstash"
  config :sev, :validate => :number, :default => 6

  config :fields, :validate => :array

  public
  def initialize(params={})
    super(params)
  end

  public
  def decode(data)
    # Need to break out the headers, then return the headers as individual fields, and the extension to be processed by a filter (ie: KV)
    # %{SYSLOGDATE} %{HOST} CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
    event = LogStash::Event.new()
    if @syslog
        @logger.debug("Expecting SYSLOG headers")
        event['syslog'], data = data.split('CEF:', 1)
        # Since we have the syslog headers, lets pull them out first and put them into their own field to be handled
    else 
        # We don't have syslog headers, so we just need to remove CEF:
        data.sub! /^CEF:/, ''
    end #if @syslog
    # Now, break out the rest of the headers
    event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], event['message'] =  data.scan /(?:[^\|\\]|\\.)+/
    yield event
  end

  public
  def encode(data)
	# "CEF:0|Elasticsearch|Logstash|1.0|Signature|Name|Sev|"

	# TODO: Need to check that fields are set!

	# Signature, Name, and Sev should be set in the config, with ref to fields
	# Should also probably set the fields sent
	header = ["CEF:0", "Elasticsearch", "Logstash", "1.0", @signature, @name, @sev].join("|")
	values = @fields.map {|name| get_value(name, data)}.join(" ")
	# values = values.map {|k,v| "#{k}=#{v}"}.join(" ")
	@on_event.call(header + " " + values + "\n")
  end

  private
  def get_value(name, event)
    val = event[name]
    case val
      when Hash
        return name + "=" + val.to_json
      else
        return name + "=" + val
    end
  end

end
